#include <shibsp/Application.h>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

//#include "PseudonymDecryptor.cpp"
//#include "polypseud_lib.c"
#include <polypseud.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xmltooling::logging;
using namespace xercesc;
using namespace std;


namespace polypseud {

    class SHIBSP_DLLLOCAL PolyPseudContext : public ResolutionContext
    {
        public:
            PolyPseudContext(const vector<Attribute*>* attributes) : m_inputAttributes(attributes) {
            }

            ~PolyPseudContext() {
                for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            }

            const vector<Attribute*>* getInputAttributes() const {
                return m_inputAttributes;
            }
            vector<Attribute*>& getResolvedAttributes() {
                return m_attributes;
            }
            vector<opensaml::Assertion*>& getResolvedAssertions() {
                return m_assertions;
            }

        private:
            const vector<Attribute*>* m_inputAttributes;
            vector<Attribute*> m_attributes;
            static vector<opensaml::Assertion*> m_assertions;   // empty dummy
    };


    class SHIBSP_DLLLOCAL PolyPseudAttributeResolver : public AttributeResolver
    {
        public:
            PolyPseudAttributeResolver(const DOMElement* e);
            virtual ~PolyPseudAttributeResolver() {}

            Lockable* lock() {
                return this;
            }
            void unlock() {
            }

            ResolutionContext* createResolutionContext(
                    const Application& application,
                    const opensaml::saml2md::EntityDescriptor* issuer,
                    const XMLCh* protocol,
                    const opensaml::saml2::NameID* nameid=nullptr,
                    const XMLCh* authncontext_class=nullptr,
                    const XMLCh* authncontext_decl=nullptr,
                    const vector<const opensaml::Assertion*>* tokens=nullptr,
                    const vector<Attribute*>* attributes=nullptr
                    ) const {

                return createResolutionContext(application, nullptr, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
            }

            ResolutionContext* createResolutionContext(
                    const Application& application,
                    const GenericRequest* request,
                    const opensaml::saml2md::EntityDescriptor* issuer,
                    const XMLCh* protocol,
                    const opensaml::saml2::NameID* nameid=nullptr,
                    const XMLCh* authncontext_class=nullptr,
                    const XMLCh* authncontext_decl=nullptr,
                    const vector<const opensaml::Assertion*>* tokens=nullptr,
                    const vector<Attribute*>* attributes=nullptr
                    ) const {
                return new PolyPseudContext(attributes);
            }

            ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
                return new PolyPseudContext(&session.getAttributes());
            }

            void resolveAttributes(ResolutionContext& ctx) const;

            void getAttributeIds(vector<string>& attributes) const {

            }

        private:
            Category& m_log;
            string m_source;
            string m_dest;
            string m_privkey;
            string m_closingkey;
            int m_port;
    };

    static const XMLCh dest[] =             UNICODE_LITERAL_4(d,e,s,t);
    static const XMLCh source[] =           UNICODE_LITERAL_6(s,o,u,r,c,e);
    static const XMLCh port[] =             UNICODE_LITERAL_4(p,o,r,t);
    static const XMLCh privkey[] =          UNICODE_LITERAL_7(p,r,i,v,k,e,y);
    static const XMLCh closingkey[] =       UNICODE_LITERAL_10(c,l,o,s,i,n,g,k,e,y);

    AttributeResolver* SHIBSP_DLLLOCAL PolyPseudAttributeResolverFactory(const DOMElement* const & e)
    {
        return new PolyPseudAttributeResolver(e);
    }

};

vector<opensaml::Assertion*> polypseud::PolyPseudContext::m_assertions;

polypseud::PolyPseudAttributeResolver::PolyPseudAttributeResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".AttributeResolver.PolyPseud")),
    m_source(XMLHelper::getAttrString(e, nullptr, source)),
    m_dest(XMLHelper::getAttrString(e, nullptr, dest)),
    m_privkey(XMLHelper::getAttrString(e, nullptr, privkey)),
    m_closingkey(XMLHelper::getAttrString(e, nullptr, closingkey)),
    m_port(XMLHelper::getAttrInt(e, 4444, port))
{
    if (m_source.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires source attribute.");
    if (m_dest.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires dest attribute.");

    if (m_privkey.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires privkey attribute.");
    if (m_closingkey.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires closingkey attribute.");
}


void polypseud::PolyPseudAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    PolyPseudContext& tctx = dynamic_cast<PolyPseudContext&>(ctx);
    if (!tctx.getInputAttributes())
        return;

    for (vector<Attribute*>::const_iterator a = tctx.getInputAttributes()->begin(); a != tctx.getInputAttributes()->end(); ++a) {
        if (m_source != (*a)->getId() || (*a)->valueCount() == 0) {
            continue;
        }

        auto_ptr<SimpleAttribute> destwrapper;
        vector<string> ids(1, m_dest);
        destwrapper.reset(new SimpleAttribute(ids));

        for (size_t i = 0; i < (*a)->valueCount(); ++i) {
            //char pseudonym[1024];
            //decrypt((*a)->getSerializedValues()[i].c_str(), m_port, pseudonym);
            char *pseudonym = polypseud_decrypt_ep((*a)->getSerializedValues()[i].c_str(), m_privkey.c_str(), m_closingkey.c_str());
            destwrapper->getValues().push_back(pseudonym);
        }

        if (destwrapper.get()) {
            ctx.getResolvedAttributes().push_back(destwrapper.get());
            destwrapper.release();
        }
    }
}

