/* flow_dissector_proto_defs.h — Local protocol definitions
 *
 * These are protocol definitions specific to the flow dissector sample,
 * not reusable library code. They define custom dispatch/framing protocols
 * that don't have a corresponding proto_def in xdp2/proto_defs/.
 */

/* Local proto_def: L2TPv3 session — need 4 bytes for session_id extraction
 * (the base l2tp proto_def only requires 2 bytes minimum)
 */
static const struct xdp2_proto_def l2tp_v3_session_def __unused() = {
	.name = "L2TPv3 session",
	.min_len = 4,
};

/* Local proto_def: Geneve (simple) — skip TLV parsing, just extract inner
 * protocol and advance past the header. Reuses geneve_proto_v0 / geneve_len_v0
 * from proto_geneve.h but as a plain xdp2_proto_def (not xdp2_proto_tlvs_def).
 */
static const struct xdp2_proto_def geneve_simple_def __unused() = {
	.name = "Geneve (simple)",
	.min_len = sizeof(struct geneve_hdr),
	.ops.next_proto = geneve_proto_v0,
	.ops.len = geneve_len_v0,
	.encap = true,
};

/* Local proto_def: Ethertype dispatch — reads 2-byte ethertype and advances.
 * Used as the root of the L2 parser. The benchmark passes data starting
 * at the ethertype field (2 bytes before L3 data) after stripping
 * Ethernet + VLANs.
 *
 * LLC detection: if the ethertype value is <= 1500 (ETH_P_802_3_MIN),
 * it's actually a length field indicating an 802.2 LLC frame. In that
 * case, return the ETH_P_802_2 sentinel to dispatch to the LLC node.
 */
static inline int etype_or_llc_proto(const void *vhdr)
{
	__be16 val = *(__be16 *)vhdr;

	if (ntohs(val) <= 1500)
		return __cpu_to_be16(ETH_P_802_2);
	return val;
}

static const struct xdp2_proto_def etype_dispatch_def __unused() = {
	.name = "Ethertype dispatch",
	.min_len = 2,
	.ops.next_proto = etype_or_llc_proto,
};

/* Local proto_def: LLC (IEEE 802.2) — reads DSAP+SSAP+Control,
 * dispatches on DSAP byte. 3 bytes minimum for unnumbered frames.
 */
struct llc_hdr {
	__u8 dsap;
	__u8 ssap;
	__u8 control;
};

static inline int llc_proto(const void *vhdr)
{
	return ((struct llc_hdr *)vhdr)->dsap;
}

static const struct xdp2_proto_def llc_dispatch_def __unused() = {
	.name = "LLC",
	.min_len = sizeof(struct llc_hdr),
	.ops.next_proto = llc_proto,
};

/* Local proto_def: SNAP (IEEE 802.2 SNAP extension) — 5 bytes:
 * 3-byte OUI + 2-byte protocol ID. When OUI is 00:00:00, the
 * protocol ID is an ethertype, so dispatch to ether_table.
 */
struct snap_hdr {
	__u8 oui[3];
	__be16 protocol;
};

static inline int snap_proto(const void *vhdr)
{
	return ((struct snap_hdr *)vhdr)->protocol;
}

static const struct xdp2_proto_def snap_dispatch_def __unused() = {
	.name = "SNAP",
	.min_len = sizeof(struct snap_hdr),
	.ops.next_proto = snap_proto,
};

/* Local proto_def: STP/RSTP/MSTP (IEEE 802.1D) — validates BPDU header.
 * 3 bytes minimum: protocol_id (2) + version (1).
 * Leaf protocol — no further dispatch.
 */
struct stp_bpdu_hdr {
	__be16 protocol_id;
	__u8 version;
};

static const struct xdp2_proto_def stp_bpdu_def __unused() = {
	.name = "STP",
	.min_len = sizeof(struct stp_bpdu_hdr),
};
