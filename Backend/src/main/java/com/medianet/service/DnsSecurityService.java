package com.medianet.service;

import com.medianet.dto.DnsSecurityResultDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks the DNS security posture of a domain: SPF (anti-spoofing sender
 * policy), DMARC (email authentication/reporting policy) and CAA (which CAs
 * are allowed to issue certificates). Uses the JDK's built-in JNDI DNS
 * provider — no external dependency, since it is only doing plain TXT/CAA
 * record lookups.
 */
@Service
public class DnsSecurityService {

    private static final Logger log = LoggerFactory.getLogger(DnsSecurityService.class);
    private static final Pattern DMARC_POLICY = Pattern.compile("p=([a-zA-Z]+)");

    public DnsSecurityResultDto lookup(String rawDomain) {
        String domain = cleanDomain(rawDomain);

        String spfRecord = null;
        for (String txt : queryTxt(domain)) {
            if (txt.toLowerCase(Locale.ROOT).startsWith("v=spf1")) {
                spfRecord = txt;
                break;
            }
        }

        String dmarcRecord = null;
        String dmarcPolicy = null;
        for (String txt : queryTxt("_dmarc." + domain)) {
            if (txt.toLowerCase(Locale.ROOT).startsWith("v=dmarc1")) {
                dmarcRecord = txt;
                Matcher m = DMARC_POLICY.matcher(txt);
                if (m.find()) dmarcPolicy = m.group(1).toLowerCase(Locale.ROOT);
                break;
            }
        }

        List<String> caaRecords;
        String caaStatus;
        try {
            caaRecords = queryCaa(domain);
            caaStatus = "READY";
        } catch (Exception e) {
            log.debug("CAA lookup unavailable for {}: {}", domain, e.getMessage());
            caaRecords = List.of();
            caaStatus = "NOT_TESTED";
        }

        return new DnsSecurityResultDto(
                domain, spfRecord, spfRecord != null,
                dmarcRecord, dmarcRecord != null, dmarcPolicy,
                caaRecords, caaStatus);
    }

    private List<String> queryTxt(String name) {
        List<String> results = new ArrayList<>();
        try {
            DirContext ctx = dnsContext();
            Attributes attrs = ctx.getAttributes(name, new String[]{"TXT"});
            Attribute txt = attrs.get("TXT");
            if (txt != null) {
                NamingEnumeration<?> values = txt.getAll();
                while (values.hasMore()) {
                    results.add(stripQuotes(String.valueOf(values.next())));
                }
            }
        } catch (Exception e) {
            log.debug("TXT lookup failed for {}: {}", name, e.getMessage());
        }
        return results;
    }

    private List<String> queryCaa(String name) throws Exception {
        List<String> results = new ArrayList<>();
        DirContext ctx = dnsContext();
        Attributes attrs = ctx.getAttributes(name, new String[]{"CAA"});
        Attribute caa = attrs.get("CAA");
        if (caa != null) {
            NamingEnumeration<?> values = caa.getAll();
            while (values.hasMore()) {
                results.add(String.valueOf(values.next()));
            }
        }
        return results;
    }

    private static DirContext dnsContext() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        return new InitialDirContext(env);
    }

    private static String stripQuotes(String value) {
        String v = value.trim();
        if (v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2) {
            v = v.substring(1, v.length() - 1);
        }
        return v;
    }

    private static String cleanDomain(String raw) {
        String d = raw.trim().toLowerCase(Locale.ROOT);
        d = d.replaceFirst("^https?://", "");
        if (d.contains("/")) d = d.substring(0, d.indexOf('/'));
        if (d.contains(":") && d.lastIndexOf(':') > d.lastIndexOf(']')) {
            d = d.substring(0, d.lastIndexOf(':'));
        }
        return d;
    }
}
