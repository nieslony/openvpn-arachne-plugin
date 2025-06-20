
/*
 * This file was automatically generated by sdbus-c++-xml2cpp; DO NOT EDIT!
 */

#ifndef __sdbuscpp__firewalld_proxy_sdbus_2_FirewallD1_Config_IpSet_Proxy_h__proxy__H__
#define __sdbuscpp__firewalld_proxy_sdbus_2_FirewallD1_Config_IpSet_Proxy_h__proxy__H__

#include <sdbus-c++/sdbus-c++.h>
#include <string>
#include <tuple>

namespace org {
namespace fedoraproject {
namespace FirewallD1 {
namespace config {

class ipset_proxy
{
public:
    static constexpr const char* INTERFACE_NAME = "org.fedoraproject.FirewallD1.config.ipset";

protected:
    ipset_proxy(sdbus::IProxy& proxy)
        : m_proxy(proxy)
    {
    }

    ipset_proxy(const ipset_proxy&) = delete;
    ipset_proxy& operator=(const ipset_proxy&) = delete;
    ipset_proxy(ipset_proxy&&) = delete;
    ipset_proxy& operator=(ipset_proxy&&) = delete;

    ~ipset_proxy() = default;

    void registerProxy()
    {
        m_proxy.uponSignal("Updated").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onUpdated(name); });
        m_proxy.uponSignal("Removed").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onRemoved(name); });
        m_proxy.uponSignal("Renamed").onInterface(INTERFACE_NAME).call([this](const std::string& name){ this->onRenamed(name); });
    }

    virtual void onUpdated(const std::string& name) = 0;
    virtual void onRemoved(const std::string& name) = 0;
    virtual void onRenamed(const std::string& name) = 0;

public:
    sdbus::Struct<std::string, std::string, std::string, std::string, std::map<std::string, std::string>, std::vector<std::string>> getSettings()
    {
        sdbus::Struct<std::string, std::string, std::string, std::string, std::map<std::string, std::string>, std::vector<std::string>> result;
        m_proxy.callMethod("getSettings").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void update(const sdbus::Struct<std::string, std::string, std::string, std::string, std::map<std::string, std::string>, std::vector<std::string>>& settings)
    {
        m_proxy.callMethod("update").onInterface(INTERFACE_NAME).withArguments(settings);
    }

    void loadDefaults()
    {
        m_proxy.callMethod("loadDefaults").onInterface(INTERFACE_NAME);
    }

    void remove()
    {
        m_proxy.callMethod("remove").onInterface(INTERFACE_NAME);
    }

    void rename(const std::string& name)
    {
        m_proxy.callMethod("rename").onInterface(INTERFACE_NAME).withArguments(name);
    }

    std::string getVersion()
    {
        std::string result;
        m_proxy.callMethod("getVersion").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setVersion(const std::string& version)
    {
        m_proxy.callMethod("setVersion").onInterface(INTERFACE_NAME).withArguments(version);
    }

    std::string getShort()
    {
        std::string result;
        m_proxy.callMethod("getShort").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setShort(const std::string& short_)
    {
        m_proxy.callMethod("setShort").onInterface(INTERFACE_NAME).withArguments(short_);
    }

    std::string getDescription()
    {
        std::string result;
        m_proxy.callMethod("getDescription").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setDescription(const std::string& description)
    {
        m_proxy.callMethod("setDescription").onInterface(INTERFACE_NAME).withArguments(description);
    }

    std::string getType()
    {
        std::string result;
        m_proxy.callMethod("getType").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setType(const std::string& ipset_type)
    {
        m_proxy.callMethod("setType").onInterface(INTERFACE_NAME).withArguments(ipset_type);
    }

    std::map<std::string, std::string> getOptions()
    {
        std::map<std::string, std::string> result;
        m_proxy.callMethod("getOptions").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setOptions(const std::map<std::string, std::string>& options)
    {
        m_proxy.callMethod("setOptions").onInterface(INTERFACE_NAME).withArguments(options);
    }

    void addOption(const std::string& key, const std::string& value)
    {
        m_proxy.callMethod("addOption").onInterface(INTERFACE_NAME).withArguments(key, value);
    }

    void removeOption(const std::string& key)
    {
        m_proxy.callMethod("removeOption").onInterface(INTERFACE_NAME).withArguments(key);
    }

    bool queryOption(const std::string& key, const std::string& value)
    {
        bool result;
        m_proxy.callMethod("queryOption").onInterface(INTERFACE_NAME).withArguments(key, value).storeResultsTo(result);
        return result;
    }

    std::vector<std::string> getEntries()
    {
        std::vector<std::string> result;
        m_proxy.callMethod("getEntries").onInterface(INTERFACE_NAME).storeResultsTo(result);
        return result;
    }

    void setEntries(const std::vector<std::string>& entries)
    {
        m_proxy.callMethod("setEntries").onInterface(INTERFACE_NAME).withArguments(entries);
    }

    void addEntry(const std::string& entry)
    {
        m_proxy.callMethod("addEntry").onInterface(INTERFACE_NAME).withArguments(entry);
    }

    void removeEntry(const std::string& entry)
    {
        m_proxy.callMethod("removeEntry").onInterface(INTERFACE_NAME).withArguments(entry);
    }

    bool queryEntry(const std::string& entry)
    {
        bool result;
        m_proxy.callMethod("queryEntry").onInterface(INTERFACE_NAME).withArguments(entry).storeResultsTo(result);
        return result;
    }

public:
    std::string name()
    {
        return m_proxy.getProperty("name").onInterface(INTERFACE_NAME).get<std::string>();
    }

    std::string filename()
    {
        return m_proxy.getProperty("filename").onInterface(INTERFACE_NAME).get<std::string>();
    }

    std::string path()
    {
        return m_proxy.getProperty("path").onInterface(INTERFACE_NAME).get<std::string>();
    }

    bool default_()
    {
        return m_proxy.getProperty("default").onInterface(INTERFACE_NAME).get<bool>();
    }

    bool builtin()
    {
        return m_proxy.getProperty("builtin").onInterface(INTERFACE_NAME).get<bool>();
    }

private:
    sdbus::IProxy& m_proxy;
};

}}}} // namespaces

#endif
