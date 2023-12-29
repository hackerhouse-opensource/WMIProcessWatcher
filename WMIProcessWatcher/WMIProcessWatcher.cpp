/* WMI Process Watcher
* ====================
* A technique to asynchronously detect when a process is created using WMI. The technique requires an 
* EventSink object that contains a reference to a callback.  Registering the aynchronous detection is 
* done by calling ExecNotificationQueryAsync() with the proper WQL async query and a pointer to the EventSink object.
*
* The queries need to detect creation and deletion of processes are as follows:
* 
* SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'
* SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'
*
* The callbacks must have the following signature:
*
* void __cdecl CallBack(long lObjectCount, IWbemClassObject **apObjArray)
* 
* Recreated from the CIA's Vault7 archives.
* 
* Hacker Fantastic
* -- https://hacker.house 
*/
#include <iostream>
#include <wbemidl.h>
#include <comutil.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

class EventSink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;

public:
    EventSink() { m_lRef = 0; }
    ~EventSink() { bDone = true; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray
    );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        /* [in] */ LONG lFlags,
        /* [in] */ HRESULT hResult,
        /* [in] */ BSTR strParam,
        /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
    );
};

ULONG EventSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (lRef == 0)
        delete this;
    return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}


HRESULT EventSink::Indicate(LONG lObjectCount, IWbemClassObject** apObjArray)
{
    HRESULT hres = S_OK;

    for (int i = 0; i < lObjectCount; i++)
    {
        VARIANT varName;
        hres = apObjArray[i]->Get(_bstr_t(L"TargetInstance"), 0, &varName, 0, 0);

        if (!FAILED(hres) && varName.vt == VT_UNKNOWN)
        {
            IUnknown* str = V_UNKNOWN(&varName);
            IWbemClassObject* pObj;
            str->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&pObj));

            VARIANT vtProp;
            // Get the value of the Name property
            hres = pObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (!FAILED(hres))
            {
                printf("Process: %ls\n", vtProp.bstrVal);
                VariantClear(&vtProp);
            }
            pObj->Release();
        }
        VariantClear(&varName);
    }

    return WBEM_S_NO_ERROR;
}

HRESULT EventSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam)
{
    if (lFlags == WBEM_STATUS_COMPLETE)
    {
        printf("Call complete. hResult = 0x%X\n", hResult);
    }
    else if (lFlags == WBEM_STATUS_PROGRESS)
    {
        printf("Call in progress.\n");
    }

    return WBEM_S_NO_ERROR;
}

int main()
{
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        printf("Failed to initialize COM library. Error code = 0x%X\n", hres);
        return 1;                  // Program has failed.
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service                  
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation
        NULL,                        // Authentication info 
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres))
    {
        printf("Failed to initialize security. Error code = 0x%X\n", hres);
        CoUninitialize();
        return 1;                    // Program has failed.
    }

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        printf("Failed to create IWbemLocator object. Err code = 0x%X\n", hres);
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    IWbemServices* pSvc = NULL;

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags
        0,                       // Authority
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
    );

    if (FAILED(hres))
    {
        printf("Could not connect. Error code = 0x%X\n", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    printf("Connected to ROOT\\CIMV2 WMI namespace\n");

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        printf("Could not set proxy blanket. Error code = 0x%X\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    EventSink* pSink = new EventSink;
    pSink->AddRef();

    // The ExecNotificationQueryAsync method will call
    // The EventQuery::Indicate method when an event occurs
    hres = pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pSink
    );

    // Check if the query was successful
    if (FAILED(hres))
    {
        printf("ExecNotificationQueryAsync failed with = 0x%X\n", hres);
        pSvc->Release();
        pLoc->Release();
        pSink->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Wait for the user to press a key before exiting
    printf("Press any key to exit...\n");
    getchar();

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pSink->Release();
    CoUninitialize();

    return 0;
}