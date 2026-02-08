# Response Committed During Stapler JEXL Evaluation

## Issue Summary

When accessing `/user/<id>/security/` pages in Jenkins, the MFA filter was encountering `IllegalStateException: Response is committed` errors when attempting to redirect users who hadn't completed MFA verification.

## Root Cause

The response was being committed by Jenkins' Stapler framework during JEXL expression evaluation while rendering the user security page, before the filter could redirect.

## Technical Deep Dive

### 1. Servlet Filter Chain Execution Order

When a request arrives, filters execute in order before the servlet/Stapler handles the request:

```
Request → Filter1 → Filter2 → MFAFilter → ... → Stapler Servlet → Jelly View → Response
```

The critical execution path in `MFAFilter.doFilter()`:

```java
// Allow certain paths to pass through without MFA check
if (shouldAllowPath(req)) {
    chain.doFilter(req, resp);
    return;
}

Optional<User> user = JenkinsUtil.getCurrentUser();

// If user is not authenticated, let them through to login page
if (user.isEmpty()) {
    chain.doFilter(req, resp);
    return;
}

// User is authenticated, check if MFA verification is required
if (!handleMFAVerification(req, resp, user.get())) {
    // MFA verification failed or pending, don't continue the chain
    return;
}

// MFA verified or not required, continue with the request
chain.doFilter(req, resp);
```

### 2. What "Response Committed" Means

A response is considered **committed** when:
- HTTP response headers are sent to the client, **or**
- Any part of the response body is flushed to the client

Once committed, you **cannot**:
- Change status codes
- Add/modify headers (including `Location` for redirects)
- Call `sendRedirect()` or `forward()`

Attempting to do so results in an `IllegalStateException`.

### 3. The Problem Sequence

For `/user/dev/security/` before the fix, here's what happened:

1. **Request arrives**: `/user/dev/security/`
2. **Filter checks `shouldAllowPath()`**: Returns `false` (path not in allowed list)
3. **Filter proceeds**: User is authenticated, so filter continues to MFA verification logic
4. **Stapler starts processing**:
   - Routes to the `User` object for `/user/dev/security/`
   - Begins rendering the Jelly view (`/user/security/config.jelly` or similar)
5. **JEXL evaluation begins**:
   - Jelly evaluates expressions like `${instance.protectedPassword}`
   - These expressions write to the response output stream
   - HTTP headers are sent (status 200, content-type, etc.)
   - **Response becomes committed**
6. **Filter tries to redirect**:
   - If MFA verification fails, `handleMFAVerification()` calls `resp.sendRedirect()`
   - But response is already committed → `IllegalStateException`

### 4. Why JEXL Evaluation Commits the Response

Jelly/JEXL rendering writes output **incrementally**:

```jelly
<!-- Simplified example of what happens -->
<l:layout title="Security">
  <!-- Headers sent here - RESPONSE COMMITTED -->
  <l:main-panel>
    <!-- JEXL evaluation happens here -->
    ${instance.protectedPassword}  <!-- This writes to response -->
    <!-- More HTML written to response stream -->
  </l:main-panel>
</l:layout>
```

When Stapler renders:
1. It sends HTTP headers **immediately** (status 200, content-type, etc.)
2. It starts writing HTML to the response stream
3. JEXL expressions are evaluated and their output is written **immediately**
4. The response buffer may flush early (depending on buffer size)

Once headers are sent or any output is flushed, the response is **committed**.

### 5. Why the Filter Couldn't Redirect

The key issue is **timing**: The filter needs to decide whether to redirect **before** calling `chain.doFilter()`. Once `chain.doFilter()` is called and Stapler starts rendering, the response commits and redirects become impossible.

The original code had a race condition:
- Path not in allowed list → proceeds to MFA check
- If MFA check determines redirect is needed, but `chain.doFilter()` was already called (or Stapler started rendering), response is committed

### 6. The Solution

Two changes were implemented to fix this:

#### Fix 1: Allow the Security Path Early

```java
// Allow user-scoped security page (/user/<id>/security and subpaths) without MFA,
// otherwise users cannot access their security configuration page.
if (relativePath.matches("^/user/[^/]+/security($|/.*)")) {
    return true;
}
```

This ensures the filter returns early (line 81) without calling `chain.doFilter()` if MFA isn't verified, preventing Stapler from starting rendering.

#### Fix 2: Check if Response is Committed Before Redirecting

```java
// Redirect to MFA input page (only if response is not already committed)
if (!resp.isCommitted()) {
    resp.sendRedirect(
        req.getContextPath() + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
    );
}
```

This provides a safety check to prevent attempting redirects after the response is committed.

## Key Takeaways

1. **Filter decisions must happen before `chain.doFilter()`**: Once you call `chain.doFilter()`, downstream components (like Stapler) can start committing the response.

2. **Stapler/JEXL rendering commits early**: Headers and initial HTML are sent as soon as rendering begins, not after the entire page is generated.

3. **Always check `isCommitted()` before redirecting**: This provides a safety net if the response has already been committed.

4. **Whitelist paths that need early access**: User configuration pages (like `/user/<id>/security/`) should be allowed early to prevent rendering from starting before MFA checks complete.

## Related Files

- `src/main/java/io/jenkins/plugins/openmfa/MFAFilter.java` - Main filter implementation
- `src/main/java/io/jenkins/plugins/openmfa/MFAPlugin.java` - Filter registration

## Error Message

```
WARNING h.ExpressionFactory2$JexlExpression#evaluate: Caught exception evaluating:
instance.protectedPassword in /jenkins/user/dev/security/.
Reason: java.lang.reflect.InvocationTargetException
java.lang.IllegalStateException: Response is committed
```

## References

- [Java Servlet Specification - Response Committed](https://jakarta.ee/specifications/servlet/)
- [Jenkins Stapler Framework](https://stapler.kohsuke.org/)
- [JEXL Expression Language](https://commons.apache.org/proper/commons-jexl/)
