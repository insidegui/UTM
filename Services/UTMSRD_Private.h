//
// Copyright © 2025 Turing Software, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once

#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#if !TARGET_OS_OSX && WITH_SRD

#pragma mark - Security SPI

#pragma clang diagnostic ignored "-Wincomplete-umbrella"

#import <Security/Security.h>

extern const CFStringRef _Nonnull kSecCodeInfoFlags;

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0,
};

typedef struct CF_BRIDGED_TYPE(id) __SecCode const *SecStaticCodeRef;    /* code on disk */

OSStatus SecStaticCodeCreateWithPath(CFURLRef __nonnull path, SecCSFlags flags, SecStaticCodeRef * __nonnull CF_RETURNS_RETAINED staticCode);

OSStatus SecCodeCopySigningInformation(SecStaticCodeRef __nonnull code, SecCSFlags flags, CFDictionaryRef * __nonnull CF_RETURNS_RETAINED information);

#pragma mark - OS Variant

extern int os_variant_allows_security_research(__unused const char * __nullable subsystem);

#endif
