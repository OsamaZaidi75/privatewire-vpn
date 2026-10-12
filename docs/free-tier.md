# Free-tier deployment notes (pointers, not promises)

> Cloud free tiers change constantly. Treat everything below as a starting
> point and **verify current terms, bandwidth caps, eligibility, and billing
> traps on the provider's own page** before deploying. This project assumes
> no free tier exists — any paid VM with a public IPv4 works.

- **Oracle Cloud Always Free** (historically the most generous for VPNs):
  2 ARM VMs (combined up to 4 OCPUs / 24 GB RAM), boot volumes, and
  substantial egress. Caveats: credit-card required, "always free" resources
  can be reclaimed when idle, availability varies by region.
- **Google Cloud**: trial credit + a monthly e2-micro allowance in select
  regions. Egress overages bill quickly.
- **AWS**: 12-month free tier (t2/t3.micro ~750 h/month). A VPN running
  24/7 consumes the full allowance of one instance; bandwidth overages apply.
- **Azure**: 12-month + always-free B1s allowance (750 h/month). Same
  bandwidth caution.
- **Others** (Hetzner/Scaleway/OVH have no permanent free tier but
  €3–5/month ARM/x86 VMs that are excellent VPN hosts).

Bandwidth rule of thumb: a personal VPN uses little when idle (keepalives
are bytes), but video/f downloads count fully against egress quotas. Set
billing alerts on day one.
