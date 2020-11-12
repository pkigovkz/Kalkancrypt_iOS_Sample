//
//  Base64.h
//  XmlTest
//
//  Created by aslan on 1/5/16.
//  Copyright © 2016 knca. All rights reserved.
//

#ifndef Base64_h
#define Base64_h

#include <stdio.h>
#include <openssl/pem.h>

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);
char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

#endif /* Base64_h */
