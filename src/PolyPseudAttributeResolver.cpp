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
    };

    static const XMLCh dest[] =             UNICODE_LITERAL_4(d,e,s,t);
    static const XMLCh source[] =           UNICODE_LITERAL_6(s,o,u,r,c,e);

    AttributeResolver* SHIBSP_DLLLOCAL PolyPseudAttributeResolverFactory(const DOMElement* const & e)
    {
        return new PolyPseudAttributeResolver(e);
    }

};

vector<opensaml::Assertion*> polypseud::PolyPseudContext::m_assertions;

polypseud::PolyPseudAttributeResolver::PolyPseudAttributeResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".AttributeResolver.PolyPseud")),
    m_source(XMLHelper::getAttrString(e, nullptr, source)),
    m_dest(XMLHelper::getAttrString(e, nullptr, dest))
{
    if (m_source.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires source attribute.");

    if (m_dest.empty())
        throw ConfigurationException("PolyPseud AttributeResolver requires dest attribute.");

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
            destwrapper->getValues().push_back("thisIsAPseudonym");
        }

        if (destwrapper.get()) {
            ctx.getResolvedAttributes().push_back(destwrapper.get());
            destwrapper.release();
        }
    }
}

