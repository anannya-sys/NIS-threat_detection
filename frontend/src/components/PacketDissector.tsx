export default function PacketDissector({ packet }: any) {
    return <div style={{ padding: '1rem' }}><h3>Packet Dissector</h3><pre>{JSON.stringify(packet, null, 2)}</pre></div>
}