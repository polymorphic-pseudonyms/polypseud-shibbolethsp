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
 * polypseud.cpp
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
# define POLYPSEUD_EXPORTS __declspec(dllexport)
#else
# define POLYPSEUD_EXPORTS
#endif

#include <memory>

#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/attribute/AttributeDecoder.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#include "PolyPseudAttributeResolver.cpp"

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

using namespace polypseud;

/*namespace {
    class SHIBSP_DLLLOCAL PolyPseudAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        PolyPseudAttributeDecoder(const DOMElement* e) : AttributeDecoder(e) {}
        ~PolyPseudAttributeDecoder() {}
        
        // deprecated method
        shibsp::Attribute* decode(
                const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const {
            return decode(nullptr, ids, xmlObject, assertingParty, relyingParty);
        }
        
        shibsp::Attribute* decode(
                const GenericRequest*, const vector<string>&, const XMLObject*, const char* assertingParty=nullptr, const char* relyingParty=nullptr
                ) const;
    };
    
    AttributeDecoder* SHIBSP_DLLLOCAL PolyPseudAttributeDecoderFactory(const DOMElement* const & e)
    {
        Category& log = Category::getInstance(SHIBSP_LOGCAT ".AttributeDecoder.PolyPseud");
        log.info("Called polypseud factory");

        return new PolyPseudAttributeDecoder(e);
    }

    static const XMLCh _PolyPseudAttributeDecoder[] = UNICODE_LITERAL_25(P,o,l,y,P,s,e,u,d,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);

    const char* decrypt(const char* input)
    {
        return "thisIsAPseudonym";
    }
};

shibsp::Attribute* PolyPseudAttributeDecoder::decode(
        const GenericRequest* request, const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
        ) const
{
    auto_ptr<SimpleAttribute> simple(new SimpleAttribute(ids));
    vector<string>& dest = simple->getValues();
    pair<vector<XMLObject*>::const_iterator,vector<XMLObject*>::const_iterator> valrange;
    
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".AttributeDecoder.PolyPseud");
    
    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            valrange = valueRange(request, values);
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                        "decoding SimpleAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                        ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                        );
            }
        }
        else {
            const opensaml::saml1::Attribute* saml1attr = dynamic_cast<const opensaml::saml1::Attribute*>(xmlObject);
            if (saml1attr) {
                const vector<XMLObject*>& values = saml1attr->getAttributeValues();
                valrange = valueRange(request, values);
                if (log.isDebugEnabled()) {
                    auto_ptr_char n(saml1attr->getAttributeName());
                    log.debug(
                            "decoding SimpleAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                            ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                            );
                }
            }
            else {
                log.warn("XMLObject type not recognized by StringAttributeDecoder, no values returned");
                return nullptr;
            }
        }

        for (; valrange.first != valrange.second; ++valrange.first) {
            if (!(*valrange.first)->hasChildren()) {
                auto_arrayptr<char> val(toUTF8((*valrange.first)->getTextContent()));
                if (val.get() && *val.get())
                    dest.push_back(decrypt(val.get()));
                else
                    log.warn("skipping empty AttributeValue");
            }
            else {
                log.warn("skipping complex AttributeValue");
            }
        }

        return dest.empty() ? nullptr : _decode(simple.release());
    }

    const NameID* saml2name = dynamic_cast<const NameID*>(xmlObject);
    if (saml2name) {
        if (log.isDebugEnabled()) {
            auto_ptr_char f(saml2name->getFormat());
            log.debug("decoding SimpleAttribute (%s) from SAML 2 NameID with Format (%s)", ids.front().c_str(), f.get() ? f.get() : "unspecified");
        }
        auto_arrayptr<char> val(toUTF8(saml2name->getName()));
        if (val.get() && *val.get())
            dest.push_back(decrypt(val.get()));
        else
            log.warn("ignoring empty NameID");
    }
    else {
        const NameIdentifier* saml1name = dynamic_cast<const NameIdentifier*>(xmlObject);
        if (saml1name) {
            if (log.isDebugEnabled()) {
                auto_ptr_char f(saml1name->getFormat());
                log.debug(
                        "decoding SimpleAttribute (%s) from SAML 1 NameIdentifier with Format (%s)",
                        ids.front().c_str(), f.get() ? f.get() : "unspecified"
                        );
            }
            auto_arrayptr<char> val(toUTF8(saml1name->getName()));
            if (val.get() && *val.get())
                dest.push_back(decrypt(val.get()));
            else
                log.warn("ignoring empty NameIdentifier");
        }
        else {
            log.warn("XMLObject type not recognized by StringAttributeDecoder, no values returned");
            return nullptr;
        }
    }

    return dest.empty() ? nullptr : _decode(simple.release());
}*/


extern "C" int POLYPSEUD_EXPORTS xmltooling_extension_init(void*)
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".AttributeResolver.PolyPseud");
    log.info("Start loading polypseud");
    // Register factory functions with appropriate plugin managers in the XMLTooling/SAML/SPConfig objects.
#ifndef SHIBSP_LITE
    //xmltooling::QName PolyPseudAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _PolyPseudAttributeDecoder);
    SPConfig& conf=SPConfig::getConfig();
    //conf.AttributeDecoderManager.registerFactory(PolyPseudAttributeDecoderType, PolyPseudAttributeDecoderFactory);
    conf.AttributeResolverManager.registerFactory("polypseud", PolyPseudAttributeResolverFactory);
    log.info("Registered polypseud factory");
#else
    log.info("Lite: no polypseud factory registered");
#endif
    return 0;   // signal success
}

extern "C" void POLYPSEUD_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}


