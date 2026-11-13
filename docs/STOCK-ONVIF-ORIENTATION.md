<!-- SPDX-License-Identifier: MIT -->
# Stock ONVIF video orientation (static analysis, V3.5.2.1 web_server)

Why Surveillance Station's "Video Orientation" panel (Mirror, Flip, Rotate) was disabled, and what
stock does. Static only; [C] = read in code, [G] = guess.

- **Capabilities [C]:** Media1/Media2 GetServiceCapabilities (`0x68878`, `0x689a0`) and GetServices
  (`0x57058`) report `Rotation="false"`, `OSD="true"`, and no VideoSourceMode.
- **Get [C]:** only the single Media1 GetVideoSourceConfiguration (`0x63a50`) adds
  `tt:Extension/tt:Rotate {Mode, Degree}`. Mode/Degree pack the web HFlip/VFlip as bits: OFF/0
  = none, ON/90 = HFlip, ON/180 = VFlip, ON/270 = both. This is a vendor encoding, not a rotation.
  The plural Get, GetProfiles and Media2 have no Rotate.
- **Options and Set [C]:** RotateOptions (Mode OFF/ON, DegreeList 90/180/270) and a working Media1
  SetVideoSourceConfiguration Rotate exist only when `/opt/ch/onvif_expand` exists. That file is
  absent on the owner's live image, so over ONVIF stock offers no options and silently ignores a
  Rotate. Media2 SetVideoSourceConfiguration is not implemented.
- **EFlip [C]:** PTZ only, advertised but not backed by anything. Imaging has no flip.
- **Mirror alone / flip alone:** only through the vendor Degree encoding above, behind the flag.

**Ours (camhttpd):** the standard meaning. `Rotation="true"`; Rotate in every
tt:VideoSourceConfiguration; options Mode OFF/ON with DegreeList 180; SetVideoSourceConfiguration
Rotate OFF (or ON 0) = no mirror/flip, ON 180 = mirror + flip (`image.mirror`/`image.flip`,
#133). 90/270 wait for a real rotation (#123). Every Rotate a client sends is logged, so SSS's
mapping of its separate Mirror/Flip dropdowns shows in the log.
