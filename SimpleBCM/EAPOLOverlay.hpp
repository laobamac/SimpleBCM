//
//  EAPOLOverlay.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/22.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_EAPOLOVERLAY_HPP
#define SIMPLEBCM_EAPOLOVERLAY_HPP

#include <IOKit/IOService.h>

namespace bcm {
void prepareEAPOLOverlay();
void publishEAPOLOverlay(IOService *service);
}

#endif
