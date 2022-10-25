﻿using System;

namespace TameMyCerts.Enums
{
    // From CertSrv.h
    [Flags]
    public enum EditFlag : uint
    {
        EDITF_ENABLEREQUESTEXTENSIONS = 0x00000001,
        EDITF_REQUESTEXTENSIONLIST = 0x00000002,
        EDITF_DISABLEEXTENSIONLIST = 0x00000004,
        EDITF_ADDOLDKEYUSAGE = 0x00000008,
        EDITF_ADDOLDCERTTYPE = 0x00000010,
        EDITF_ATTRIBUTEENDDATE = 0x00000020,
        EDITF_BASICCONSTRAINTSCRITICAL = 0x00000040,
        EDITF_BASICCONSTRAINTSCA = 0x00000080,
        EDITF_ENABLEAKIKEYID = 0x00000100,
        EDITF_ATTRIBUTECA = 0x00000200,
        EDITF_IGNOREREQUESTERGROUP = 0x00000400,
        EDITF_ENABLEAKIISSUERNAME = 0x00000800,
        EDITF_ENABLEAKIISSUERSERIAL = 0x00001000,
        EDITF_ENABLEAKICRITICAL = 0x00002000,
        EDITF_SERVERUPGRADED = 0x00004000,
        EDITF_ATTRIBUTEEKU = 0x00008000,
        EDITF_ENABLEDEFAULTSMIME = 0x00010000,
        EDITF_EMAILOPTIONAL = 0x00020000,
        EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000,
        EDITF_ENABLELDAPREFERRALS = 0x00080000,
        EDITF_ENABLECHASECLIENTDC = 0x00100000,
        EDITF_AUDITCERTTEMPLATELOAD = 0x00200000,
        EDITF_DISABLEOLDOSCNUPN = 0x00400000,
        EDITF_DISABLELDAPPACKAGELIST = 0x00800000,
        EDITF_ENABLEUPNMAP = 0x01000000,
        EDITF_ENABLEOCSPREVNOCHECK = 0x02000000,
        EDITF_ENABLERENEWONBEHALFOF = 0x04000000
    }
}