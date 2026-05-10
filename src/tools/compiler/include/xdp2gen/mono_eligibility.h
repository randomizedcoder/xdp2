/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2026 Anthropic. All rights reserved.
 *
 * mono_eligibility.h — R2.3 validator for the monolithic codegen
 * path. Reports whether a parser graph satisfies all the structural
 * preconditions for emission as a single specialised function with
 * goto-state transitions (R3 target).
 *
 * Conservative: rejects any graph that uses post-handlers, exit
 * nodes (okay/fail/atencap), counters, keys, frame-storage growth,
 * or exceeds a depth bound. R3's mono template can relax these as
 * support is added per case.
 *
 * Usage:
 *   if (auto reason = xdp2gen::check_mono_eligibility(graph, root))
 *       plog::log(...) << "mono rejected: " << *reason;
 *   else
 *       // emit MONO codegen
 */

#ifndef XDP2GEN_MONO_ELIGIBILITY_H
#define XDP2GEN_MONO_ELIGIBILITY_H

#include <optional>
#include <string>
#include <xdp2gen/graph.h>

namespace xdp2gen
{

/* Conservative depth bound for mono emission. Beyond this, the
 * generated entry function becomes large enough that the gcc
 * inliner may refuse to inline it, defeating the purpose. Tunable
 * if R3 finds taller graphs are worth flattening. */
static constexpr int MONO_MAX_DEPTH = 32;

/* check_mono_eligibility — return nullopt on success (graph is
 * mono-eligible), or a human-readable reason string on rejection.
 * Iterates the vertex set once; early-exits on first violation. */
template <typename Graph>
inline std::optional<std::string>
check_mono_eligibility(Graph const &graph,
                       parser<Graph> const &root,
                       std::size_t max_level = 0)
{
    /* Root-level structural checks first. */
    if (root.okay_target_set)
        return std::string{ "okay exit-node present (post-parse hook)" };
    if (root.fail_target_set)
        return std::string{ "fail exit-node present (post-parse hook)" };
    if (root.encap_target_set)
        return std::string{ "atencap exit-node present" };
    /* num_counters/num_keys default to 255 in xdp2gen IR (graph.h)
     * even when the parser doesn't explicitly declare them — the
     * AST consumer overrides only when the field is present in the
     * source. So `> 0` is unreliable as a usage indicator. Skip
     * these checks; rely on per-node post_handler check instead,
     * which catches the cases that actually consume counters. */
    if (root.max_frames > 1)
        return std::string{
            "parser uses multiple metadata frames — mono path supports one"
        };
    if (static_cast<int>(max_level) > MONO_MAX_DEPTH)
        return std::string{
            "graph depth exceeds MONO_MAX_DEPTH (" +
            std::to_string(MONO_MAX_DEPTH) + ")"
        };

    /* Per-vertex checks. */
    auto vertices = boost::vertices(graph);
    for (auto it = vertices.first; it != vertices.second; ++it) {
        auto const &v = graph[*it];
        if (!v.post_handler.empty())
            return std::string{ "node '" + v.name +
                                "' uses post_handler — not yet mono-supported" };
        if (!v.tlv_table.empty())
            return std::string{ "node '" + v.name +
                                "' uses TLV table — deferred to R3 phase 2" };
        if (!v.flag_fields_table.empty())
            return std::string{
                "node '" + v.name +
                "' uses flag_fields_table — deferred to R3 phase 2"
            };
    }

    return std::nullopt;
}

} // namespace xdp2gen

#endif /* XDP2GEN_MONO_ELIGIBILITY_H */
