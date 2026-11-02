<!--
  NOTICE.md
  SimpleBCM

  Created by laobamac on 2026/9/21.
  Copyright © 2026 laobamac. All rights reserved.
-->
# Third-party components

Copyright © 2026 laobamac. All rights reserved. Third-party components retain their own licenses and copyright.

- [Lilu](https://github.com/acidanthera/Lilu) is a user-supplied dependency of optional AirportBrcmFixup and retains its upstream license and copyright.
- [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK) and its SDK headers and libraries retain their original licenses and copyright.
- [OpenCore Legacy Patcher](https://github.com/dortania/OpenCore-Legacy-Patcher) supplies the pinned wireless archives. Packages include `OCLP-LICENSE.txt` for the patcher project; that license does not replace the terms of individual bundled components.
- `IO80211FamilyLegacy.kext` and `AirPortBrcmNIC-Tahoe.kext` are Apple driver components from those upstream archives. The universal adapter embeds Legacy and both the original and Tahoe AirPort variants, registering only Legacy and the selected AirPort variant on each boot. The old `IOSkywalkFamily.kext` is an offline ABI reference and is not embedded or shipped as a driver. Apple's proprietary components remain subject to Apple's applicable terms.
- [AirportBrcmFixup](https://github.com/acidanthera/AirportBrcmFixup) and its injector retain their upstream license and copyright.
- [Apple configd](https://github.com/apple-oss-distributions/configd) was consulted to verify SystemConfiguration interface classification. Its source is an offline research reference and is not compiled or distributed in the driver.

Dependency revisions and archive hashes are pinned in `Tools/bootstrap.py`. Build preparation verifies the upstream revisions, archive hashes, and extracted bytes. Local dependency checkouts, build output, and distribution packages are excluded from the source repository.
