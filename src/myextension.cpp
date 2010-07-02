/*
 *  Copyright 2010 Example Org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * myextension.cpp
 *
 * Extension library for Shibboleth SP
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define MYEXT_EXPORTS __declspec(dllexport)
#else
# define MYEXT_EXPORTS
#endif

#include <memory>

#include <shibsp/base.h>
#include <shibsp/exceptions.h>
#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <saml/SAMLConfig.h>
#endif
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

extern "C" int MYEXT_EXPORTS xmltooling_extension_init(void*)
{
    // Register factory functions with appropriate plugin managers in the XMLTooling/SAML/SPConfig objects.
    return 0;   // signal success
}

extern "C" void MYEXT_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
