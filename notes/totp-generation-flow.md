# TOTP Generation Flow

## Overview

TOTP (Time-based One-Time Password) is a cryptographic algorithm that generates time-limited authentication codes, typically 6-8 digits, valid for 30-60 seconds. Defined in RFC 6238, TOTP extends HOTP (HMAC-based One-Time Password) by using time instead of a counter as the dynamic variable.

## Key Properties

- **Short-lived**: Codes typically expire every 30 seconds
- **Shared secret**: Both authenticator app and server hold the same secret key
- **Offline capable**: Authenticator apps can generate codes without internet connectivity
- **Widely supported**: Used across banking, cloud apps, social media, and enterprise logins
- **Time-based**: Uses Unix timestamp divided into fixed intervals (commonly 30 seconds)

## TOTP Generation Process

### Step 1: Shared Secret Initialization

During onboarding, a **shared secret key** is established between the server and the authenticator app:

- Server generates a unique secret key (random bytes, often Base32-encoded)
- Secret is embedded in a URI using the `otpauth://` scheme
- URI is displayed as a QR code for easy scanning
- Authenticator app scans QR code and securely stores the secret key
- Both parties now share the same secret, which never leaves the device/server

**Example URI format:**
```
otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp
```

### Step 2: Time Counter Calculation

TOTP uses **time** as the dynamic variable instead of a counter:

- Current Unix timestamp is divided by a time step (typically **30 seconds**)
- This produces a **time counter** that increments every 30 seconds
- Formula: `time_counter = floor(current_unix_timestamp / time_step)`

**Example:**
- At Unix time `1696602030`, dividing by 30 gives `56553401`
- This counter value increases every 30 seconds

### Step 3: HMAC Computation

The system combines the secret key and time counter using HMAC (Hash-Based Message Authentication Code):

- Algorithm: HMAC-SHA-1 (or HMAC-SHA-256, HMAC-SHA-512)
- Input: `HMAC-SHA-1(secret_key, time_counter)`
- Output: A 160-bit (20-byte) hash value

### Step 4: Dynamic Truncation

The long hash value is converted to a shorter integer using **dynamic truncation**:

- Extract a 4-byte segment from the HMAC result
- Convert to a 31-bit integer (masking the most significant bit)
- This provides a pseudo-random number for the final code

### Step 5: Modulo Operation → Final OTP Code

The integer is reduced to the desired number of digits using modulo:

- Formula: `OTP = truncate_value mod 10^d`
- Where `d` is the number of digits (commonly **6**)
- Result: A 6-digit code like `482915`

**Complete TOTP Formula:**
```
TOTP = (HMAC-SHA-1(secret_key, floor(current_timestamp / time_step))) mod 10^d
```

## Server Validation Process

### 1. Shared Secret Storage

- The server stores the same secret key that was shared during onboarding
- Secret is typically encrypted and linked to the user's account

### 2. Server-Side TOTP Regeneration

When a user submits a TOTP code:

- Server regenerates the TOTP for the current time window using the same algorithm
- Uses the stored secret key and current timestamp
- Computes: `TOTP = (HMAC-SHA-1(secret_key, floor(current_timestamp / 30))) mod 10^6`

### 3. Tolerance Window

To handle clock drift and network delays, servers check a **tolerance window**:

- Typically validates codes for: `current_window ± 1 step` (±30 seconds)
- Allows codes to be valid even if entered a few seconds late
- Prevents authentication failures due to minor clock synchronization issues

### 4. Comparison and Decision

- Server compares the user's submitted code against generated values in the tolerance window
- If any match: **Access granted** ✅
- If no match: **Access denied** ❌ (user prompted to try again)

**Example Timeline:**
- Time window `12:00:00–12:00:30` → Code = `482915`
- User enters code at `12:00:28` → Server checks `12:00:00–12:00:30` → Match ✅
- User enters code at `12:00:32` → Server checks `12:00:30–12:01:00` → Still valid ✅
- After tolerance expires → Code rejected ❌

## TOTP vs HOTP Comparison

| Feature | HOTP (RFC 4226) | TOTP (RFC 6238) |
|---------|----------------|-----------------|
| **Base Algorithm** | HMAC-SHA-1 | HMAC-SHA-1 |
| **Dynamic Variable** | Incrementing counter | Unix timestamp/time-step |
| **Validity Period** | Until used or next generation | 30-60 seconds (typically) |
| **Synchronization** | Requires counter sync | Automatic via system clocks |
| **Offline Operation** | Fully supported | Requires initial time sync |
| **Clock Dependency** | None | Critical (±30s tolerance) |
| **Replay Attack Risk** | Medium (longer validity) | Low (short window) |
| **User Experience** | Can cause confusion | More intuitive |

## Security Advantages

### 1. Short Lifespan
- Codes expire every ~30 seconds, making intercepted codes useless almost immediately

### 2. Secret Never Transmitted
- Only the generated 6-digit codes are sent, never the raw secret key
- Secret key remains securely stored on device and server

### 3. Resistant to Replay Attacks
- Old codes cannot be reused because their time window has expired

### 4. Offline Capability
- Codes generated locally, avoiding SMS/email interception vulnerabilities
- No dependency on network connectivity for code generation

### 5. Stronger than SMS 2FA
- Avoids SIM swapping and SS7 protocol exploits
- Code generation happens inside the device, not over vulnerable channels

## Limitations

### 1. Phishing Vulnerability
- Users can be tricked into entering codes on fake websites
- Attackers can use codes in real-time within the 30-second window
- TOTP alone doesn't protect against man-in-the-middle attacks

### 2. Single Device Dependency
- Secret key tied to specific authenticator app/device
- Device loss or reset can lock users out without backup codes

### 3. Clock Synchronization
- Requires reasonably accurate clocks (±30 seconds tolerance)
- Significant clock drift can cause authentication failures

### 4. No Built-in Transport Security
- TOTP only generates the code
- Website must use HTTPS to protect code transmission

### 5. User Experience Trade-off
- Requires opening app, reading code, and manual entry
- Adds friction compared to password-only logins

## Real-World Example: Banking Login

1. **User logs in** with username and password
2. **Server prompts** for 6-digit TOTP code
3. **User opens authenticator app** (e.g., Google Authenticator)
4. **App displays code** like `482915` with countdown timer
5. **User enters code** on banking website
6. **Server validates** by regenerating TOTP and comparing
7. **Access granted** if code matches within tolerance window

## Implementation Considerations

### Time Step Selection
- **30 seconds**: Most common, balances security and usability
- **60 seconds**: Longer validity, less secure
- Shorter steps increase security but reduce usability

### Code Length
- **6 digits**: Most common (1,000,000 possible values)
- **8 digits**: Higher security (100,000,000 possible values)
- Longer codes are more secure but harder to enter

### Hash Algorithm
- **HMAC-SHA-1**: Standard, widely supported
- **HMAC-SHA-256**: Stronger, recommended for new implementations
- **HMAC-SHA-512**: Strongest, less common

### Clock Synchronization
- Servers should use NTP (Network Time Protocol) for accurate time
- Tolerance window (±1 step) handles minor clock drift
- Users may need to sync device clock if authentication fails

## References

- [TOTP Demystified - Medium Article](https://medium.com/@raditya.mit/totp-demystified-how-time-based-one-time-passwords-secure-your-logins-3798339ed29c)
- [OTP vs HOTP vs TOTP - EngageLab Blog](https://www.engagelab.com/blog/otp-hotp-totp)
- RFC 6238: TOTP: Time-Based One-Time Password Algorithm
- RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm
