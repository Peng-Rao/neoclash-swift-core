/// A single hand-rolled userspace TCP connection: it terminates the app's TCP flow that arrives on
/// the TUN interface and exposes the byte stream to the proxy side via callbacks. Because the TUN
/// path is a lossless in-memory link, this is a deliberately minimal TCP — proper sequence/ack
/// tracking, peer-window flow control, and half-close teardown, but no congestion control and no
/// retransmission timers (the app retransmits if needed; our segments are never dropped in memory).
///
/// All methods must be invoked on a single event loop (the stack's); the class is not internally
/// synchronized.
final class SwiftCoreTCPConnection {
    enum State {
        case synReceived
        case established
        case closed
    }

    let source: [UInt8]          // the app's address (we send back to it)
    let sourcePort: Int
    let destination: [UInt8]     // the target the app dialed (we spoof it as our source)
    let destinationPort: Int

    private let emit: ([UInt8]) -> Void
    private let mss = 1400
    private let receiveWindow: UInt16 = 0xFFFF
    /// Pause the proxy read side once this many bytes are queued toward the app; resume when drained.
    private let highWaterMark = 256 * 1024

    private(set) var state: State = .synReceived
    private var receiveNext: UInt32 = 0     // next sequence number expected from the app
    private var sendNext: UInt32 = 0        // next sequence number we will send
    private var sendUnacked: UInt32 = 0     // oldest of our bytes not yet acked by the app
    private var peerWindow = 0

    private var pendingOut: [UInt8] = []     // proxy -> app bytes not yet segmented out
    private var finQueued = false            // send our FIN once pendingOut drains
    private var finSent = false
    private var appFinished = false
    private var readPaused = false

    /// Fired once the three-way handshake completes; the controller dials the proxy here.
    var onEstablished: ((SwiftCoreTCPConnection) -> Void)?
    /// App -> proxy application bytes.
    var onAppData: (([UInt8]) -> Void)?
    /// The connection is fully torn down; the controller closes the proxy channel.
    var onClosed: (() -> Void)?
    /// The queue toward the app crossed/receded the high-water mark; controller pauses/resumes reads.
    var onReadPauseChanged: ((Bool) -> Void)?

    init(source: [UInt8], sourcePort: Int, destination: [UInt8], destinationPort: Int, emit: @escaping ([UInt8]) -> Void) {
        self.source = source
        self.sourcePort = sourcePort
        self.destination = destination
        self.destinationPort = destinationPort
        self.emit = emit
    }

    // MARK: Inbound (from the app, via the TUN)

    /// Handles the opening SYN and replies with SYN-ACK.
    func start(with segment: SwiftCoreTCPSegment) {
        receiveNext = segment.sequenceNumber &+ 1     // SYN consumes one sequence number
        sendNext = UInt32.random(in: 0...UInt32.max)  // our ISN
        sendUnacked = sendNext
        peerWindow = Int(segment.window)
        send(flags: SwiftCoreTCPFlag.syn | SwiftCoreTCPFlag.ack, sequence: sendNext, payload: [])
        sendNext = sendNext &+ 1                       // our SYN consumes one sequence number
    }

    /// Handles every segment after the opening SYN.
    func receive(_ segment: SwiftCoreTCPSegment) {
        guard state != .closed else { return }
        if segment.isRST {
            teardown()
            return
        }
        peerWindow = Int(segment.window)
        if segment.isACK {
            acknowledge(segment.acknowledgmentNumber)
        }

        if state == .synReceived, segment.isACK, segment.acknowledgmentNumber == sendNext {
            state = .established
            onEstablished?(self)
        }

        if !segment.payload.isEmpty {
            if segment.sequenceNumber == receiveNext {
                receiveNext = receiveNext &+ UInt32(segment.payload.count)
                onAppData?(segment.payload)
            }
            // In-order or not, acknowledge what we have (prompts retransmit of anything missing).
            sendAck()
        }

        if segment.isFIN, segment.sequenceNumber &+ UInt32(segment.payload.count) == receiveNext {
            receiveNext = receiveNext &+ 1             // FIN consumes one sequence number
            appFinished = true
            sendAck()
            closeIfDone()
        }

        flush()
    }

    // MARK: Outbound (from the proxy)

    /// Queues proxy bytes to send to the app.
    func deliverToApp(_ bytes: [UInt8]) {
        guard state != .closed, !finQueued else { return }
        pendingOut.append(contentsOf: bytes)
        flush()
        updateReadPause()
    }

    /// The proxy side finished sending; send our FIN after any queued data drains.
    func proxyDidClose() {
        guard state != .closed else { return }
        finQueued = true
        flush()
    }

    /// Aborts the connection with a RST toward the app (e.g. the proxy dial failed).
    func reset() {
        guard state != .closed else { return }
        send(flags: SwiftCoreTCPFlag.rst | SwiftCoreTCPFlag.ack, sequence: sendNext, payload: [])
        teardown()
    }

    // MARK: Internals

    private func acknowledge(_ ackNumber: UInt32) {
        if seqDiff(ackNumber, sendUnacked) > 0, seqDiff(ackNumber, sendNext) <= 0 {
            sendUnacked = ackNumber
        }
        if finSent, appFinished, ackNumber == sendNext {
            closeIfDone()
        }
        updateReadPause()
    }

    private func flush() {
        while !pendingOut.isEmpty {
            let inflight = Int(seqDiff(sendNext, sendUnacked))
            let available = peerWindow - inflight
            guard available > 0 else { break }
            let count = min(mss, available, pendingOut.count)
            let chunk = Array(pendingOut.prefix(count))
            pendingOut.removeFirst(count)
            send(flags: SwiftCoreTCPFlag.psh | SwiftCoreTCPFlag.ack, sequence: sendNext, payload: chunk)
            sendNext = sendNext &+ UInt32(count)
        }
        if finQueued, !finSent, pendingOut.isEmpty {
            send(flags: SwiftCoreTCPFlag.fin | SwiftCoreTCPFlag.ack, sequence: sendNext, payload: [])
            sendNext = sendNext &+ 1
            finSent = true
        }
        updateReadPause()
    }

    private func closeIfDone() {
        // Fully closed once the app has finished, we have sent our FIN, and it has been acknowledged.
        if appFinished, finSent, sendUnacked == sendNext {
            teardown()
        }
    }

    private func teardown() {
        guard state != .closed else { return }
        state = .closed
        pendingOut.removeAll()
        onClosed?()
    }

    private func updateReadPause() {
        let shouldPause = pendingOut.count >= highWaterMark
        if shouldPause != readPaused {
            readPaused = shouldPause
            onReadPauseChanged?(shouldPause)
        }
    }

    private func sendAck() {
        send(flags: SwiftCoreTCPFlag.ack, sequence: sendNext, payload: [])
    }

    private func send(flags: UInt8, sequence: UInt32, payload: [UInt8]) {
        let packet = SwiftCoreTCPSegment.build(
            source: destination,
            destination: source,
            sourcePort: destinationPort,
            destinationPort: sourcePort,
            sequenceNumber: sequence,
            acknowledgmentNumber: receiveNext,
            flags: flags,
            window: receiveWindow,
            payload: payload
        )
        emit(packet)
    }

    /// Signed sequence-space difference `a - b`, correct across the 32-bit wraparound.
    private func seqDiff(_ a: UInt32, _ b: UInt32) -> Int32 {
        Int32(bitPattern: a &- b)
    }
}
