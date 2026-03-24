/* Wrapper for xdp2-compiler: define XDP2_XDP_BUILD to exclude the
 * L2 parser (xdp2-compiler's .xdp.h output supports a single root).
 */
#define XDP2_XDP_BUILD
#include "parser.c"
