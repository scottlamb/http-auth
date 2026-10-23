# RFC excerpts for `bearer`

Verbatim from the RFCs the `bearer` module implements; page headers removed.
See [20261023-bearer.md](20261023-bearer.md).

## RFC 6750 section 2.1: Authorization Request Header Field

```text
2.1.  Authorization Request Header Field

   When sending the access token in the "Authorization" request header
   field defined by HTTP/1.1 [RFC2617], the client uses the "Bearer"
   authentication scheme to transmit the access token.

   For example:

     GET /resource HTTP/1.1
     Host: server.example.com
     Authorization: Bearer mF_9.B5f-4.1JqM

   The syntax of the "Authorization" header field for this scheme
   follows the usage of the Basic scheme defined in Section 2 of
   [RFC2617].  Note that, as with Basic, it does not conform to the
   generic syntax defined in Section 1.2 of [RFC2617] but is compatible
   with the general authentication framework being developed for
   HTTP 1.1 [HTTP-AUTH], although it does not follow the preferred
   practice outlined therein in order to reflect existing deployments.
   The syntax for Bearer credentials is as follows:

     b64token    = 1*( ALPHA / DIGIT /
                       "-" / "." / "_" / "~" / "+" / "/" ) *"="
     credentials = "Bearer" 1*SP b64token

   Clients SHOULD make authenticated requests with a bearer token using
   the "Authorization" request header field with the "Bearer" HTTP
   authorization scheme.  Resource servers MUST support this method.
```

## RFC 6750 section 3: The WWW-Authenticate Response Header Field

```text
3.  The WWW-Authenticate Response Header Field

   If the protected resource request does not include authentication
   credentials or does not contain an access token that enables access
   to the protected resource, the resource server MUST include the HTTP
   "WWW-Authenticate" response header field; it MAY include it in
   response to other conditions as well.  The "WWW-Authenticate" header
   field uses the framework defined by HTTP/1.1 [RFC2617].

   All challenges defined by this specification MUST use the auth-scheme
   value "Bearer".  This scheme MUST be followed by one or more
   auth-param values.  The auth-param attributes used or defined by this
   specification are as follows.  Other auth-param attributes MAY be
   used as well.

   A "realm" attribute MAY be included to indicate the scope of
   protection in the manner described in HTTP/1.1 [RFC2617].  The
   "realm" attribute MUST NOT appear more than once.

   The "scope" attribute is defined in Section 3.3 of [RFC6749].  The
   "scope" attribute is a space-delimited list of case-sensitive scope
   values indicating the required scope of the access token for
   accessing the requested resource. "scope" values are implementation
   defined; there is no centralized registry for them; allowed values
   are defined by the authorization server.  The order of "scope" values
   is not significant.  In some cases, the "scope" value will be used

   when requesting a new access token with sufficient scope of access to
   utilize the protected resource.  Use of the "scope" attribute is
   OPTIONAL.  The "scope" attribute MUST NOT appear more than once.  The
   "scope" value is intended for programmatic use and is not meant to be
   displayed to end-users.

   Two example scope values follow; these are taken from the OpenID
   Connect [OpenID.Messages] and the Open Authentication Technology
   Committee (OATC) Online Multimedia Authorization Protocol [OMAP]
   OAuth 2.0 use cases, respectively:

     scope="openid profile email"
     scope="urn:example:channel=HBO&urn:example:rating=G,PG-13"

   If the protected resource request included an access token and failed
   authentication, the resource server SHOULD include the "error"
   attribute to provide the client with the reason why the access
   request was declined.  The parameter value is described in
   Section 3.1.  In addition, the resource server MAY include the
   "error_description" attribute to provide developers a human-readable
   explanation that is not meant to be displayed to end-users.  It also
   MAY include the "error_uri" attribute with an absolute URI
   identifying a human-readable web page explaining the error.  The
   "error", "error_description", and "error_uri" attributes MUST NOT
   appear more than once.

   Values for the "scope" attribute (specified in Appendix A.4 of
   [RFC6749]) MUST NOT include characters outside the set %x21 / %x23-5B
   / %x5D-7E for representing scope values and %x20 for delimiters
   between scope values.  Values for the "error" and "error_description"
   attributes (specified in Appendixes A.7 and A.8 of [RFC6749]) MUST
   NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
   Values for the "error_uri" attribute (specified in Appendix A.9 of
   [RFC6749]) MUST conform to the URI-reference syntax and thus MUST NOT
   include characters outside the set %x21 / %x23-5B / %x5D-7E.

   For example, in response to a protected resource request without
   authentication:

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example"

   And in response to a protected resource request with an
   authentication attempt using an expired access token:

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example",
                       error="invalid_token",
                       error_description="The access token expired"

3.1.  Error Codes

   When a request fails, the resource server responds using the
   appropriate HTTP status code (typically, 400, 401, 403, or 405) and
   includes one of the following error codes in the response:

   invalid_request
         The request is missing a required parameter, includes an
         unsupported parameter or parameter value, repeats the same
         parameter, uses more than one method for including an access
         token, or is otherwise malformed.  The resource server SHOULD
         respond with the HTTP 400 (Bad Request) status code.

   invalid_token
         The access token provided is expired, revoked, malformed, or
         invalid for other reasons.  The resource SHOULD respond with
         the HTTP 401 (Unauthorized) status code.  The client MAY
         request a new access token and retry the protected resource
         request.

   insufficient_scope
         The request requires higher privileges than provided by the
         access token.  The resource server SHOULD respond with the HTTP
         403 (Forbidden) status code and MAY include the "scope"
         attribute with the scope necessary to access the protected
         resource.

   If the request lacks any authentication information (e.g., the client
   was unaware that authentication is necessary or attempted using an
   unsupported authentication method), the resource server SHOULD NOT
   include an error code or other error information.

   For example:

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example"
```

## RFC 6749 appendix A.4, A.7-A.9: `scope`, `error`, `error_description`, `error_uri` syntax

```text
Appendix A.  Augmented Backus-Naur Form (ABNF) Syntax

   This section provides Augmented Backus-Naur Form (ABNF) syntax
   descriptions for the elements defined in this specification using the
   notation of [RFC5234].  The ABNF below is defined in terms of Unicode
   code points [W3C.REC-xml-20081126]; these characters are typically
   encoded in UTF-8.  Elements are presented in the order first defined.

   Some of the definitions that follow use the "URI-reference"
   definition from [RFC3986].

   Some of the definitions that follow use these common definitions:

     VSCHAR     = %x20-7E
     NQCHAR     = %x21 / %x23-5B / %x5D-7E
     NQSCHAR    = %x20-21 / %x23-5B / %x5D-7E
     UNICODECHARNOCRLF = %x09 /%x20-7E / %x80-D7FF /
                         %xE000-FFFD / %x10000-10FFFF

   (The UNICODECHARNOCRLF definition is based upon the Char definition
   in Section 2.2 of [W3C.REC-xml-20081126], but omitting the Carriage
   Return and Linefeed characters.)

A.4.  "scope" Syntax

   The "scope" element is defined in Section 3.3:

     scope       = scope-token *( SP scope-token )
     scope-token = 1*NQCHAR

A.7.  "error" Syntax

   The "error" element is defined in Sections 4.1.2.1, 4.2.2.1, 5.2,
   7.2, and 8.5:

     error             = 1*NQSCHAR

A.8.  "error_description" Syntax

   The "error_description" element is defined in Sections 4.1.2.1,
   4.2.2.1, 5.2, and 7.2:

     error-description = 1*NQSCHAR

A.9.  "error_uri" Syntax

   The "error_uri" element is defined in Sections 4.1.2.1, 4.2.2.1, 5.2,
   and 7.2:

     error-uri         = URI-reference
```

## RFC 9728 section 1.2: Terminology (resource identifier)

```text
1.2.  Terminology

   This specification uses the terms "access token", "authorization
   code", "authorization server", "client", "client authentication",
   "client identifier", "protected resource", and "resource server"
   defined by OAuth 2.0 [RFC6749], and the terms "Claim Name" and "JSON
   Web Token (JWT)" defined by "JSON Web Token (JWT)" [JWT].

   This specification defines the following term:

   Resource Identifier:
      The protected resource's resource identifier, which is a URL that
      uses the https scheme and has no fragment component.  As specified
      in Section 2 of [RFC8707], it also SHOULD NOT include a query
      component, but it is recognized that there are cases that make a
      query component a useful and necessary part of a resource
      identifier.  Protected resource metadata is published at a .well-
      known location [RFC8615] derived from this resource identifier, as
      described in Section 3.
```

## RFC 9728 sections 5.1-5.2: WWW-Authenticate Response

```text
5.1.  WWW-Authenticate Response

   This specification introduces a new parameter in the WWW-Authenticate
   HTTP response header field to indicate the protected resource
   metadata URL:

   resource_metadata:
      The URL of the protected resource metadata.

   The response below is an example of a WWW-Authenticate header that
   includes the resource identifier.

   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: Bearer resource_metadata=
     "https://resource.example.com/.well-known/oauth-protected-resource"

   The HTTP status code in the example response above is defined by
   [RFC6750].

   This parameter MAY also be used in WWW-Authenticate responses using
   authorization schemes other than "Bearer" [RFC6750], such as the DPoP
   scheme defined by [RFC9449].

   The resource_metadata parameter MAY be combined with other parameters
   defined in other extensions, such as the max_age parameter defined by
   [RFC9470].

5.2.  Changes to Resource Metadata

   At any point, for any reason determined by the resource server, the
   protected resource MAY respond with a new WWW-Authenticate challenge
   that includes a value for the protected resource metadata URL to
   indicate that its metadata may have changed.  If the client receives
   such a WWW-Authenticate response, it SHOULD retrieve the updated
   protected resource metadata and use the new metadata values obtained,
   after validating them as described in Section 3.3.  Among other
   things, this enables a resource server to change which authorization
   servers it uses without any other coordination with clients.
```

## RFC 3986 appendix A: Collected ABNF for URI

```text
Appendix A.  Collected ABNF for URI

   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

   hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty

   URI-reference = URI / relative-ref

   absolute-URI  = scheme ":" hier-part [ "?" query ]

   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]

   relative-part = "//" authority path-abempty
                 / path-absolute
                 / path-noscheme
                 / path-empty

   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

   authority     = [ userinfo "@" ] host [ ":" port ]
   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
   host          = IP-literal / IPv4address / reg-name
   port          = *DIGIT

   IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"

   IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

   IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"

   h16           = 1*4HEXDIG
   ls32          = ( h16 ":" h16 ) / IPv4address
   IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet

   dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255

   reg-name      = *( unreserved / pct-encoded / sub-delims )

   path          = path-abempty    ; begins with "/" or is empty
                 / path-absolute   ; begins with "/" but not "//"
                 / path-noscheme   ; begins with a non-colon segment
                 / path-rootless   ; begins with a segment
                 / path-empty      ; zero characters

   path-abempty  = *( "/" segment )
   path-absolute = "/" [ segment-nz *( "/" segment ) ]
   path-noscheme = segment-nz-nc *( "/" segment )
   path-rootless = segment-nz *( "/" segment )
   path-empty    = 0<pchar>

   segment       = *pchar
   segment-nz    = 1*pchar
   segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
                 ; non-zero-length segment without any colon ":"

   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

   query         = *( pchar / "/" / "?" )

   fragment      = *( pchar / "/" / "?" )

   pct-encoded   = "%" HEXDIG HEXDIG

   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
   reserved      = gen-delims / sub-delims
   gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="
```
