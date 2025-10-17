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

#include "UTMSRD.h"
#include "UTMSRD_Private.h"

bool srd_allows_security_research(void)
{
#if TARGET_OS_OSX
    return false;
#elif !WITH_SRD
    return false;
#else
    return os_variant_allows_security_research(NULL);
#endif
}

#if WITH_SRD

NSDictionary *app_entitlements(void) {
    OSStatus status = errSecSuccess;
    #define SecAPIValidate( api ) \
    if (status != errSecSuccess) { \
        NSLog(@"%s failed with %d (%@)", #api, status, SecCopyErrorMessageString(status, NULL)); \
        goto cleanup; \
    }

    NSDictionary *entitlements = nil;
    CFDictionaryRef information = NULL;

    NSURL *executableURL = NSBundle.mainBundle.executableURL;
    if (!executableURL) return nil;

    SecStaticCodeRef staticCode;
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)executableURL, kSecCSDefaultFlags, &staticCode);
    SecAPIValidate(SecCodeCopyStaticCode);

    status = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &information);
    SecAPIValidate(SecCodeCopySigningInformation);

    entitlements = [(__bridge NSDictionary *)information objectForKey:@"entitlements-dict"];
    if (!entitlements) NSLog(@"Signing information is missing entitlements-dict!");

cleanup:
    if (staticCode != NULL) CFRelease(staticCode);
    if (information != NULL) CFRelease(information);
    return entitlements;
}

#endif
