
/*
 * This file was automatically generated by sdbus-c++-xml2cpp; DO NOT EDIT!
 */

#ifndef __sdbuscpp__firewalld_proxy_sdbus_1_FirewallD1_Config_Policy_Proxy_h__proxy__H__
#define __sdbuscpp__firewalld_proxy_sdbus_1_FirewallD1_Config_Policy_Proxy_h__proxy__H__

#include <sdbus-c++/sdbus-c++.h>
#include <string>
#include <tuple>

namespace org {
namespace fedoraproject {
namespace FirewallD1 {
namespace config {

class policy_proxy
{
public:
    static constexpr const char* INTERFACE_NAME = "org.fedoraproject.FirewallD1.config.policy";

protected:
    policy_proxy(sdbus::IProxy& proxy)
        : proxy_(&proxy)
    {
        proxy_->uponSignal("Updated").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onUpdated(name); });
        proxy_->uponSignal("Removed").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onRemoved(name); });
        proxy_->uponSignal("Renamed").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onRenamed(name); });
    }

    policy_proxy(const policy_proxy&) = delete;
    policy_proxy& operator=(const policy_proxy&) = delete;
    policy_proxy(policy_proxy&&) = default;
    policy_proxy& operator=(policy_proxy&&) = default;

    ~policy_proxy() = default;

    virtual void onUpdated(const std::string& name) = 0;
    virtual void onRemoved(const std::string& name) = 0;
    virtual void onRenamed(const std::string& name) = 0;

public:
    std::map<std::string, sdbus::Variant> getSettings()
    {
        std::map<std::string, sdbus::Variant> result;
        proxy_->callMethod("getSettings").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void update(const std::map<std::string, sdbus::Variant>& settings)
    {
        proxy_->callMethod("update").onInterface(INTERFACE_NAME).withArguments(settings);
    }

    void loadDefaults()
    {
        proxy_->callMethod("loadDefaults").onInterface(INTERFACE_NAME);
    }

    void remove()
    {
        proxy_->callMethod("remove").onInterface(INTERFACE_NAME);
    }

    void rename(const std::string& name)
    {
        proxy_->callMethod("rename").onInterface(INTERFACE_NAME).withArguments(name);
    }

public:
    std::string name()
    {
        return proxy_->getProperty("name").onInterface(INTERFACE_NAME);
    }

    std::string filename()
    {
        return proxy_->getProperty("filename").onInterface(INTERFACE_NAME);
    }

    std::string path()
    {
        return proxy_->getProperty("path").onInterface(INTERFACE_NAME);
    }

    bool default_()
    {
        return proxy_->getProperty("default").onInterface(INTERFACE_NAME);
    }

    bool builtin()
    {
        return proxy_->getProperty("builtin").onInterface(INTERFACE_NAME);
    }

private:
    sdbus::IProxy* proxy_;
};

}}}} // namespaces

#endif
