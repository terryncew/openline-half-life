# Third-party and pinned-source notices

`src/openline_half_life/vendor/openline_endurance_gate/succession.py` is an unchanged copy of the Succession Calibrator source from OpenLine Endurance Gate v0.10.0, aligned to release commit `6c6f740`.

Pinned SHA-256:

`0fd92bdfed08107a6826f03131fe6f076744deaad2785b4177c56f484cb35d12`

The file is used as the canonical source for metric directions, threshold fitting, persistence fitting, canonical signing, and policy hashing. OpenLine Half-Life does not carry a replacement COLE equation implementation.

The v0.1.1 demonstration policy is signed once with a release key whose private half is not distributed. Verification requires the receiver-owned public key in `policy/succession_policy_public_key.hex` and independently recomputes the unsigned policy body with the pinned fitter.
