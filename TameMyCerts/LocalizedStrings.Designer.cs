﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TameMyCerts {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class LocalizedStrings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal LocalizedStrings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("TameMyCerts.LocalizedStrings", typeof(LocalizedStrings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The {0} policy module currently does not support standalone certification authorities..
        /// </summary>
        internal static string Events_MODULE_NOT_SUPPORTED {
            get {
                return ResourceManager.GetString("Events_MODULE_NOT_SUPPORTED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Error initializing Windows Default policy module:
        ///{0}.
        /// </summary>
        internal static string Events_PDEF_FAIL_INIT {
            get {
                return ResourceManager.GetString("Events_PDEF_FAIL_INIT", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Shutting down Windows Default policy module failed:
        ///{0}.
        /// </summary>
        internal static string Events_PDEF_FAIL_SHUTDOWN {
            get {
                return ResourceManager.GetString("Events_PDEF_FAIL_SHUTDOWN", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Windows Default policy module was unable to verify request {0}:
        ///{1}.
        /// </summary>
        internal static string Events_PDEF_FAIL_VERIFY {
            get {
                return ResourceManager.GetString("Events_PDEF_FAIL_VERIFY", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Request {0} was denied by the Windows Default policy module..
        /// </summary>
        internal static string Events_PDEF_REQUEST_DENIED {
            get {
                return ResourceManager.GetString("Events_PDEF_REQUEST_DENIED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0} policy module version {1} is ready to process incoming certificate requests..
        /// </summary>
        internal static string Events_PDEF_SUCCESS_INIT {
            get {
                return ResourceManager.GetString("Events_PDEF_SUCCESS_INIT", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Certificate template {0} used for Request {1} is configured to build subject from Active Directory, skipping..
        /// </summary>
        internal static string Events_POLICY_NOT_APPLICABLE {
            get {
                return ResourceManager.GetString("Events_POLICY_NOT_APPLICABLE", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to find policy file for {0}. Request {1} will get issued. Expected policy file name: &quot;{2}&quot;.
        /// </summary>
        internal static string Events_POLICY_NOT_FOUND {
            get {
                return ResourceManager.GetString("Events_POLICY_NOT_FOUND", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Request {0} for {1} was denied because:
        ///{2}.
        /// </summary>
        internal static string Events_REQUEST_DENIED {
            get {
                return ResourceManager.GetString("Events_REQUEST_DENIED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Audit mode is enabled for {1}. Request {0} would get denied because:
        ///{2}.
        /// </summary>
        internal static string Events_REQUEST_DENIED_AUDIT {
            get {
                return ResourceManager.GetString("Events_REQUEST_DENIED_AUDIT", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Request {0} contains the &quot;san&quot; request attribute, and the certification authority is configured with the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. This is a highly dangerous configuration. The request was therefore denied..
        /// </summary>
        internal static string Events_REQUEST_DENIED_INSECURE_FLAGS {
            get {
                return ResourceManager.GetString("Events_REQUEST_DENIED_INSECURE_FLAGS", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to interpret policy from {0}. Request {1} will get denied..
        /// </summary>
        internal static string Events_REQUEST_DENIED_NO_POLICY {
            get {
                return ResourceManager.GetString("Events_REQUEST_DENIED_NO_POLICY", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to No certificate template information found for request {0}. The request will get denied..
        /// </summary>
        internal static string Events_REQUEST_DENIED_NO_TEMPLATE_INFO {
            get {
                return ResourceManager.GetString("Events_REQUEST_DENIED_NO_TEMPLATE_INFO", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Cryptographic provider &quot;{0}&quot; used to create the certificate request is disallowed..
        /// </summary>
        internal static string ReqVal_Crypto_Provider_Disallowed {
            get {
                return ResourceManager.GetString("ReqVal_Crypto_Provider_Disallowed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Cryptographic provider &quot;{0}&quot; used to create the certificate request is not allowed..
        /// </summary>
        internal static string ReqVal_Crypto_Provider_Not_Allowed {
            get {
                return ResourceManager.GetString("ReqVal_Crypto_Provider_Not_Allowed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to determine the cryptographic provider that was used to create the certificate request, but policy requires this information. Probably the certificate request does not contain such information..
        /// </summary>
        internal static string ReqVal_Crypto_Provider_Unknown {
            get {
                return ResourceManager.GetString("ReqVal_Crypto_Provider_Unknown", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The value &quot;{0}&quot; does match expression &quot;{1}&quot; which is disallowed for the {2} field..
        /// </summary>
        internal static string ReqVal_Disallow_Match {
            get {
                return ResourceManager.GetString("ReqVal_Disallow_Match", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to extract inner PKCS#10 request from given CMC certificate request..
        /// </summary>
        internal static string ReqVal_Err_Extract_From_Cmc {
            get {
                return ResourceManager.GetString("ReqVal_Err_Extract_From_Cmc", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to extract inner PKCS#10 request from given PKCS#7 certificate request..
        /// </summary>
        internal static string ReqVal_Err_Extract_From_Pkcs7 {
            get {
                return ResourceManager.GetString("ReqVal_Err_Extract_From_Pkcs7", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to parse the given certificate request. Request type was {0}..
        /// </summary>
        internal static string ReqVal_Err_Parse_Request {
            get {
                return ResourceManager.GetString("ReqVal_Err_Parse_Request", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to parse the given subject distinguished name: {0}..
        /// </summary>
        internal static string ReqVal_Err_Parse_SubjectDn {
            get {
                return ResourceManager.GetString("ReqVal_Err_Parse_SubjectDn", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to match pattern &quot;{0}&quot; with value &quot;{1}&quot; for the {2} field..
        /// </summary>
        internal static string ReqVal_Err_Regex {
            get {
                return ResourceManager.GetString("ReqVal_Err_Regex", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The {0} field was found {1} times, but is allowed only {2} times..
        /// </summary>
        internal static string ReqVal_Field_Count_Mismatch {
            get {
                return ResourceManager.GetString("ReqVal_Field_Count_Mismatch", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The mandatory {0} field was not found in the request..
        /// </summary>
        internal static string ReqVal_Field_Missing {
            get {
                return ResourceManager.GetString("ReqVal_Field_Missing", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The {0} field is not allowed..
        /// </summary>
        internal static string ReqVal_Field_Not_Allowed {
            get {
                return ResourceManager.GetString("ReqVal_Field_Not_Allowed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to No allowed patterns are defined for the {0} field..
        /// </summary>
        internal static string ReqVal_Field_Not_Defined {
            get {
                return ResourceManager.GetString("ReqVal_Field_Not_Defined", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The value &quot;{0}&quot; for the {1} field exceeds the maximum allowed length of {2} characters..
        /// </summary>
        internal static string ReqVal_Field_Too_Long {
            get {
                return ResourceManager.GetString("ReqVal_Field_Too_Long", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The value &quot;{0}&quot; for the {1} field deceeds of the minimum required length of {2} characters..
        /// </summary>
        internal static string ReqVal_Field_Too_Short {
            get {
                return ResourceManager.GetString("ReqVal_Field_Too_Short", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The certificate request uses an {0} key pair, but must use an {1} key pair..
        /// </summary>
        internal static string ReqVal_Key_Pair_Mismatch {
            get {
                return ResourceManager.GetString("ReqVal_Key_Pair_Mismatch", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Key length of {0} Bits is more than the allowed maximum length of {1} Bits..
        /// </summary>
        internal static string ReqVal_Key_Too_Large {
            get {
                return ResourceManager.GetString("ReqVal_Key_Too_Large", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Key length of {0} Bits is less than the required minimum length of {1} Bits..
        /// </summary>
        internal static string ReqVal_Key_Too_Small {
            get {
                return ResourceManager.GetString("ReqVal_Key_Too_Small", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The value &quot;{0}&quot; does not match any of the allowed patterns for the {1} field..
        /// </summary>
        internal static string ReqVal_No_Match {
            get {
                return ResourceManager.GetString("ReqVal_No_Match", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Process &quot;{0}&quot; used to create the certificate request is disallowed..
        /// </summary>
        internal static string ReqVal_Process_Disallowed {
            get {
                return ResourceManager.GetString("ReqVal_Process_Disallowed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Process &quot;{0}&quot; used to create the certificate request is not allowed..
        /// </summary>
        internal static string ReqVal_Process_Not_Allowed {
            get {
                return ResourceManager.GetString("ReqVal_Process_Not_Allowed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to determine the process name that was used to create the certificate request, but policy requires this information. Probably the certificate request does not contain such information..
        /// </summary>
        internal static string ReqVal_Process_Unknown {
            get {
                return ResourceManager.GetString("ReqVal_Process_Unknown", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The certificate request contains the unsupported Subject Directory Attributes extension..
        /// </summary>
        internal static string ReqVal_Unsupported_Extension_Dir_Attrs {
            get {
                return ResourceManager.GetString("ReqVal_Unsupported_Extension_Dir_Attrs", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The certificate request contains an unsupported Subject Alternative Name type with OID {0}..
        /// </summary>
        internal static string ReqVal_Unsupported_San_Type {
            get {
                return ResourceManager.GetString("ReqVal_Unsupported_San_Type", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to unknown.
        /// </summary>
        internal static string Unknown {
            get {
                return ResourceManager.GetString("Unknown", resourceCulture);
            }
        }
    }
}
