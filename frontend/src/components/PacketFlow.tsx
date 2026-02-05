import { ArrowRight, Activity } from 'lucide-react'
import './PacketFlow.css'

interface Packet {
    src: string
    dst: string
    protocol: string
    length: number
    timestamp: string
}

interface PacketFlowProps {
    packets: Packet[]
}

export default function PacketFlow({ packets }: PacketFlowProps) {
    // Show last 15 packets
    const recentPackets = packets.slice(-15).reverse()

    return (
        <div className="packet-flow">
            <div className="flow-header">
                <Activity size={16} />
                <h3>Live Traffic</h3>
            </div>
            <div className="flow-list">
                {recentPackets.length === 0 ? (
                    <div className="flow-empty">Waiting for traffic...</div>
                ) : (
                    recentPackets.map((packet, i) => (
                        <div key={i} className="flow-item">
                            <span className="flow-time">
                                {new Date(packet.timestamp).toLocaleTimeString().split(' ')[0]}
                            </span>
                            <div className="flow-connection">
                                <span className="flow-addr src">{packet.src}</span>
                                <ArrowRight size={12} className="flow-arrow" />
                                <span className="flow-addr dst">{packet.dst}</span>
                            </div>
                            <span className={`flow-tag proto-${packet.protocol.toLowerCase()}`}>
                                {packet.protocol}
                            </span>
                        </div>
                    ))
                )}
            </div>
        </div>
    )
}