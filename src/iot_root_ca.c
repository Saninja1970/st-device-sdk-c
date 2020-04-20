/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

const unsigned char st_root_ca[] = {
  0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43,
  0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d,
  0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x72, 0x7a, 0x43, 0x43,
  0x41, 0x70, 0x65, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x51,
  0x43, 0x44, 0x76, 0x67, 0x56, 0x70, 0x42, 0x43, 0x52, 0x72, 0x47, 0x68,
  0x64, 0x57, 0x72, 0x4a, 0x57, 0x5a, 0x48, 0x48, 0x53, 0x6a, 0x41, 0x4e,
  0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42,
  0x41, 0x51, 0x55, 0x46, 0x41, 0x44, 0x42, 0x68, 0x0a, 0x4d, 0x51, 0x73,
  0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x47, 0x45, 0x77, 0x4a,
  0x56, 0x55, 0x7a, 0x45, 0x56, 0x4d, 0x42, 0x4d, 0x47, 0x41, 0x31, 0x55,
  0x45, 0x43, 0x68, 0x4d, 0x4d, 0x52, 0x47, 0x6c, 0x6e, 0x61, 0x55, 0x4e,
  0x6c, 0x63, 0x6e, 0x51, 0x67, 0x53, 0x57, 0x35, 0x6a, 0x4d, 0x52, 0x6b,
  0x77, 0x46, 0x77, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4c, 0x45, 0x78, 0x42,
  0x33, 0x0a, 0x64, 0x33, 0x63, 0x75, 0x5a, 0x47, 0x6c, 0x6e, 0x61, 0x57,
  0x4e, 0x6c, 0x63, 0x6e, 0x51, 0x75, 0x59, 0x32, 0x39, 0x74, 0x4d, 0x53,
  0x41, 0x77, 0x48, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x45, 0x78,
  0x64, 0x45, 0x61, 0x57, 0x64, 0x70, 0x51, 0x32, 0x56, 0x79, 0x64, 0x43,
  0x42, 0x48, 0x62, 0x47, 0x39, 0x69, 0x59, 0x57, 0x77, 0x67, 0x55, 0x6d,
  0x39, 0x76, 0x64, 0x43, 0x42, 0x44, 0x0a, 0x51, 0x54, 0x41, 0x65, 0x46,
  0x77, 0x30, 0x77, 0x4e, 0x6a, 0x45, 0x78, 0x4d, 0x54, 0x41, 0x77, 0x4d,
  0x44, 0x41, 0x77, 0x4d, 0x44, 0x42, 0x61, 0x46, 0x77, 0x30, 0x7a, 0x4d,
  0x54, 0x45, 0x78, 0x4d, 0x54, 0x41, 0x77, 0x4d, 0x44, 0x41, 0x77, 0x4d,
  0x44, 0x42, 0x61, 0x4d, 0x47, 0x45, 0x78, 0x43, 0x7a, 0x41, 0x4a, 0x42,
  0x67, 0x4e, 0x56, 0x42, 0x41, 0x59, 0x54, 0x41, 0x6c, 0x56, 0x54, 0x0a,
  0x4d, 0x52, 0x55, 0x77, 0x45, 0x77, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4b,
  0x45, 0x77, 0x78, 0x45, 0x61, 0x57, 0x64, 0x70, 0x51, 0x32, 0x56, 0x79,
  0x64, 0x43, 0x42, 0x4a, 0x62, 0x6d, 0x4d, 0x78, 0x47, 0x54, 0x41, 0x58,
  0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x73, 0x54, 0x45, 0x48, 0x64, 0x33,
  0x64, 0x79, 0x35, 0x6b, 0x61, 0x57, 0x64, 0x70, 0x59, 0x32, 0x56, 0x79,
  0x64, 0x43, 0x35, 0x6a, 0x0a, 0x62, 0x32, 0x30, 0x78, 0x49, 0x44, 0x41,
  0x65, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x4d, 0x54, 0x46, 0x30, 0x52,
  0x70, 0x5a, 0x32, 0x6c, 0x44, 0x5a, 0x58, 0x4a, 0x30, 0x49, 0x45, 0x64,
  0x73, 0x62, 0x32, 0x4a, 0x68, 0x62, 0x43, 0x42, 0x53, 0x62, 0x32, 0x39,
  0x30, 0x49, 0x45, 0x4e, 0x42, 0x4d, 0x49, 0x49, 0x42, 0x49, 0x6a, 0x41,
  0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x0a, 0x39, 0x77,
  0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51,
  0x38, 0x41, 0x4d, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4b, 0x43, 0x41, 0x51,
  0x45, 0x41, 0x34, 0x6a, 0x76, 0x68, 0x45, 0x58, 0x4c, 0x65, 0x71, 0x4b,
  0x54, 0x54, 0x6f, 0x31, 0x65, 0x71, 0x55, 0x4b, 0x4b, 0x50, 0x43, 0x33,
  0x65, 0x51, 0x79, 0x61, 0x4b, 0x6c, 0x37, 0x68, 0x4c, 0x4f, 0x6c, 0x6c,
  0x73, 0x42, 0x0a, 0x43, 0x53, 0x44, 0x4d, 0x41, 0x5a, 0x4f, 0x6e, 0x54,
  0x6a, 0x43, 0x33, 0x55, 0x2f, 0x64, 0x44, 0x78, 0x47, 0x6b, 0x41, 0x56,
  0x35, 0x33, 0x69, 0x6a, 0x53, 0x4c, 0x64, 0x68, 0x77, 0x5a, 0x41, 0x41,
  0x49, 0x45, 0x4a, 0x7a, 0x73, 0x34, 0x62, 0x67, 0x37, 0x2f, 0x66, 0x7a,
  0x54, 0x74, 0x78, 0x52, 0x75, 0x4c, 0x57, 0x5a, 0x73, 0x63, 0x46, 0x73,
  0x33, 0x59, 0x6e, 0x46, 0x6f, 0x39, 0x37, 0x0a, 0x6e, 0x68, 0x36, 0x56,
  0x66, 0x65, 0x36, 0x33, 0x53, 0x4b, 0x4d, 0x49, 0x32, 0x74, 0x61, 0x76,
  0x65, 0x67, 0x77, 0x35, 0x42, 0x6d, 0x56, 0x2f, 0x53, 0x6c, 0x30, 0x66,
  0x76, 0x42, 0x66, 0x34, 0x71, 0x37, 0x37, 0x75, 0x4b, 0x4e, 0x64, 0x30,
  0x66, 0x33, 0x70, 0x34, 0x6d, 0x56, 0x6d, 0x46, 0x61, 0x47, 0x35, 0x63,
  0x49, 0x7a, 0x4a, 0x4c, 0x76, 0x30, 0x37, 0x41, 0x36, 0x46, 0x70, 0x74,
  0x0a, 0x34, 0x33, 0x43, 0x2f, 0x64, 0x78, 0x43, 0x2f, 0x2f, 0x41, 0x48,
  0x32, 0x68, 0x64, 0x6d, 0x6f, 0x52, 0x42, 0x42, 0x59, 0x4d, 0x71, 0x6c,
  0x31, 0x47, 0x4e, 0x58, 0x52, 0x6f, 0x72, 0x35, 0x48, 0x34, 0x69, 0x64,
  0x71, 0x39, 0x4a, 0x6f, 0x7a, 0x2b, 0x45, 0x6b, 0x49, 0x59, 0x49, 0x76,
  0x55, 0x58, 0x37, 0x51, 0x36, 0x68, 0x4c, 0x2b, 0x68, 0x71, 0x6b, 0x70,
  0x4d, 0x66, 0x54, 0x37, 0x50, 0x0a, 0x54, 0x31, 0x39, 0x73, 0x64, 0x6c,
  0x36, 0x67, 0x53, 0x7a, 0x65, 0x52, 0x6e, 0x74, 0x77, 0x69, 0x35, 0x6d,
  0x33, 0x4f, 0x46, 0x42, 0x71, 0x4f, 0x61, 0x73, 0x76, 0x2b, 0x7a, 0x62,
  0x4d, 0x55, 0x5a, 0x42, 0x66, 0x48, 0x57, 0x79, 0x6d, 0x65, 0x4d, 0x72,
  0x2f, 0x79, 0x37, 0x76, 0x72, 0x54, 0x43, 0x30, 0x4c, 0x55, 0x71, 0x37,
  0x64, 0x42, 0x4d, 0x74, 0x6f, 0x4d, 0x31, 0x4f, 0x2f, 0x34, 0x0a, 0x67,
  0x64, 0x57, 0x37, 0x6a, 0x56, 0x67, 0x2f, 0x74, 0x52, 0x76, 0x6f, 0x53,
  0x53, 0x69, 0x69, 0x63, 0x4e, 0x6f, 0x78, 0x42, 0x4e, 0x33, 0x33, 0x73,
  0x68, 0x62, 0x79, 0x54, 0x41, 0x70, 0x4f, 0x42, 0x36, 0x6a, 0x74, 0x53,
  0x6a, 0x31, 0x65, 0x74, 0x58, 0x2b, 0x6a, 0x6b, 0x4d, 0x4f, 0x76, 0x4a,
  0x77, 0x49, 0x44, 0x41, 0x51, 0x41, 0x42, 0x6f, 0x32, 0x4d, 0x77, 0x59,
  0x54, 0x41, 0x4f, 0x0a, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x38, 0x42,
  0x41, 0x66, 0x38, 0x45, 0x42, 0x41, 0x4d, 0x43, 0x41, 0x59, 0x59, 0x77,
  0x44, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54, 0x41, 0x51, 0x48, 0x2f,
  0x42, 0x41, 0x55, 0x77, 0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a, 0x41, 0x64,
  0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x34, 0x45, 0x46, 0x67, 0x51, 0x55,
  0x41, 0x39, 0x35, 0x51, 0x4e, 0x56, 0x62, 0x52, 0x0a, 0x54, 0x4c, 0x74,
  0x6d, 0x38, 0x4b, 0x50, 0x69, 0x47, 0x78, 0x76, 0x44, 0x6c, 0x37, 0x49,
  0x39, 0x30, 0x56, 0x55, 0x77, 0x48, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30,
  0x6a, 0x42, 0x42, 0x67, 0x77, 0x46, 0x6f, 0x41, 0x55, 0x41, 0x39, 0x35,
  0x51, 0x4e, 0x56, 0x62, 0x52, 0x54, 0x4c, 0x74, 0x6d, 0x38, 0x4b, 0x50,
  0x69, 0x47, 0x78, 0x76, 0x44, 0x6c, 0x37, 0x49, 0x39, 0x30, 0x56, 0x55,
  0x77, 0x0a, 0x44, 0x51, 0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49, 0x68, 0x76,
  0x63, 0x4e, 0x41, 0x51, 0x45, 0x46, 0x42, 0x51, 0x41, 0x44, 0x67, 0x67,
  0x45, 0x42, 0x41, 0x4d, 0x75, 0x63, 0x4e, 0x36, 0x70, 0x49, 0x45, 0x78,
  0x49, 0x4b, 0x2b, 0x74, 0x31, 0x45, 0x6e, 0x45, 0x39, 0x53, 0x73, 0x50,
  0x54, 0x66, 0x72, 0x67, 0x54, 0x31, 0x65, 0x58, 0x6b, 0x49, 0x6f, 0x79,
  0x51, 0x59, 0x2f, 0x45, 0x73, 0x72, 0x0a, 0x68, 0x4d, 0x41, 0x74, 0x75,
  0x64, 0x58, 0x48, 0x2f, 0x76, 0x54, 0x42, 0x48, 0x31, 0x6a, 0x4c, 0x75,
  0x47, 0x32, 0x63, 0x65, 0x6e, 0x54, 0x6e, 0x6d, 0x43, 0x6d, 0x72, 0x45,
  0x62, 0x58, 0x6a, 0x63, 0x4b, 0x43, 0x68, 0x7a, 0x55, 0x79, 0x49, 0x6d,
  0x5a, 0x4f, 0x4d, 0x6b, 0x58, 0x44, 0x69, 0x71, 0x77, 0x38, 0x63, 0x76,
  0x70, 0x4f, 0x70, 0x2f, 0x32, 0x50, 0x56, 0x35, 0x41, 0x64, 0x67, 0x0a,
  0x30, 0x36, 0x4f, 0x2f, 0x6e, 0x56, 0x73, 0x4a, 0x38, 0x64, 0x57, 0x4f,
  0x34, 0x31, 0x50, 0x30, 0x6a, 0x6d, 0x50, 0x36, 0x50, 0x36, 0x66, 0x62,
  0x74, 0x47, 0x62, 0x66, 0x59, 0x6d, 0x62, 0x57, 0x30, 0x57, 0x35, 0x42,
  0x6a, 0x66, 0x49, 0x74, 0x74, 0x65, 0x70, 0x33, 0x53, 0x70, 0x2b, 0x64,
  0x57, 0x4f, 0x49, 0x72, 0x57, 0x63, 0x42, 0x41, 0x49, 0x2b, 0x30, 0x74,
  0x4b, 0x49, 0x4a, 0x46, 0x0a, 0x50, 0x6e, 0x6c, 0x55, 0x6b, 0x69, 0x61,
  0x59, 0x34, 0x49, 0x42, 0x49, 0x71, 0x44, 0x66, 0x76, 0x38, 0x4e, 0x5a,
  0x35, 0x59, 0x42, 0x62, 0x65, 0x72, 0x4f, 0x67, 0x4f, 0x7a, 0x57, 0x36,
  0x73, 0x52, 0x42, 0x63, 0x34, 0x4c, 0x30, 0x6e, 0x61, 0x34, 0x55, 0x55,
  0x2b, 0x4b, 0x72, 0x6b, 0x32, 0x55, 0x38, 0x38, 0x36, 0x55, 0x41, 0x62,
  0x33, 0x4c, 0x75, 0x6a, 0x45, 0x56, 0x30, 0x6c, 0x73, 0x0a, 0x59, 0x53,
  0x45, 0x59, 0x31, 0x51, 0x53, 0x74, 0x65, 0x44, 0x77, 0x73, 0x4f, 0x6f,
  0x42, 0x72, 0x70, 0x2b, 0x75, 0x76, 0x46, 0x52, 0x54, 0x70, 0x32, 0x49,
  0x6e, 0x42, 0x75, 0x54, 0x68, 0x73, 0x34, 0x70, 0x46, 0x73, 0x69, 0x76,
  0x39, 0x6b, 0x75, 0x58, 0x63, 0x6c, 0x56, 0x7a, 0x44, 0x41, 0x47, 0x79,
  0x53, 0x6a, 0x34, 0x64, 0x7a, 0x70, 0x33, 0x30, 0x64, 0x38, 0x74, 0x62,
  0x51, 0x6b, 0x0a, 0x43, 0x41, 0x55, 0x77, 0x37, 0x43, 0x32, 0x39, 0x43,
  0x37, 0x39, 0x46, 0x76, 0x31, 0x43, 0x35, 0x71, 0x66, 0x50, 0x72, 0x6d,
  0x41, 0x45, 0x53, 0x72, 0x63, 0x69, 0x49, 0x78, 0x70, 0x67, 0x30, 0x58,
  0x34, 0x30, 0x4b, 0x50, 0x4d, 0x62, 0x70, 0x31, 0x5a, 0x57, 0x56, 0x62,
  0x64, 0x34, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44,
  0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45,
  0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};
const unsigned int st_root_ca_len = 1338;
