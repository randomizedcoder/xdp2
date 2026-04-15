/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Common definition for the AF_XDP parser context.
 * Reuses the same metadata layout as flow_tracker_tmpl.
 */

#ifndef __SAMPLES_XDP_AF_XDP_PARSER_COMMON__
#define __SAMPLES_XDP_AF_XDP_PARSER_COMMON__

#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"
#include "xdp2/proto_defs_define.h"
#include "xdp2/utility.h"

struct af_xdp_parser_ctx {
	struct xdp2_xdp_ctx ctx;
	struct xdp2_metadata_all frame[1];
};

#endif /* __SAMPLES_XDP_AF_XDP_PARSER_COMMON__ */
