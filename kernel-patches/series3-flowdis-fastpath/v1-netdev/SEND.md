# How to send v1 RFC to netdev

This directory has the **send-ready** form of the series 3 v1 RFC:
the 3 patches + a tight cover letter framed as a small targeted
optimisation.

Sister directory `v1/` has the same patches with a more detailed
cover letter (kept as the comprehensive record). Use `v1-netdev/`
for `git send-email`.

## Pre-send checklist

  - [ ] Re-verify the 3 patches still pass checkpatch + W=1 build
        on net-next branch `flowdis-fastpath-rfc` (HEAD
        `e24cf9001c0b`, 2026-06-07 gate reshape).
  - [ ] Re-verify the sysctl gate behavior: build with the patches,
        boot with default (no change vs baseline), then
        `sysctl -w net.core.flow_dissector_fastpath=1` and confirm
        the fast-path engages (e.g. enable the planned selftest, or
        observe via perf top + microbench).
  - [ ] Confirm `scripts/get_maintainer.pl` output is current; the
        list below is from 2026-05-27.
  - [ ] Re-read the cover letter once with fresh eyes — note it
        now points reviewers at the v2-experiment single-patch on
        GitHub as a reading aid.

## CC list

From `scripts/get_maintainer.pl net/core/flow_dissector.c`:

```
To: netdev@vger.kernel.org

Cc: David S. Miller <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Simon Horman <horms@kernel.org>
Cc: Qingfang Deng <qingfang.deng@linux.dev>
Cc: linux-kernel@vger.kernel.org
```

Additional CC for the XDP2/PANDA-comparison context (optional):

```
Cc: Tom Herbert <tom@quantonium.net>
```

**Do not CC** Dave Täht (deceased 2025-04-01).

## Send command

From `~/Downloads/net-next` with branch `flowdis-fastpath-rfc`
checked out (HEAD `e24cf9001c0b`):

```bash
cd /home/das/Downloads/net-next

# Re-generate the per-patch files from the branch (canonical source)
git format-patch -3 --subject-prefix='PATCH RFC' \
                    --output-directory /tmp/send-flowdis/

# Optional: hand-edit the cover letter to match v1-netdev/0000-*.patch
cp /home/das/Downloads/xdp2/kernel-patches/series3-flowdis-fastpath/v1-netdev/0000-cover-letter.patch \
   /tmp/send-flowdis/0000-cover-letter.patch

# Send
git send-email \
    --to=netdev@vger.kernel.org \
    --cc='David S. Miller <davem@davemloft.net>' \
    --cc='Eric Dumazet <edumazet@google.com>' \
    --cc='Jakub Kicinski <kuba@kernel.org>' \
    --cc='Paolo Abeni <pabeni@redhat.com>' \
    --cc='Simon Horman <horms@kernel.org>' \
    --cc='Qingfang Deng <qingfang.deng@linux.dev>' \
    --cc=linux-kernel@vger.kernel.org \
    /tmp/send-flowdis/*.patch
```

## After sending

  - Capture the lore.kernel.org thread URL once it appears (search
    for the cover-letter subject on lore).
  - Update `STATUS.md` with the submission date and lore URL.
  - Watch for review feedback over 1-2 weeks; plan a v2 with any
    requested changes plus the planned follow-ups (kernel selftest,
    VLAN fast-path).
