//
//  TahoeDMA.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/8.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_TAHOE_DMA_HPP
#define SIMPLEBCM_TAHOE_DMA_HPP

#include "Payload.hpp"
#include <IOKit/IOService.h>

namespace bcm {

class TahoeDMA {
public:
    static bool prepare(LinkedImage &image, bool enabled);
    static void publish(IOService *service);
};

}

#endif
