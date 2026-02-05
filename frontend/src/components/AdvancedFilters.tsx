
export interface FilterConfig { protocols: string[]; minLength: number; maxLength: number; srcIp: string; dstIp: string; srcPort: string; dstPort: string; }
export default function AdvancedFilters({ onClose }: any) {
    return <div className="modal">Advanced Filters Modal <button onClick={onClose}>Close</button></div>
}