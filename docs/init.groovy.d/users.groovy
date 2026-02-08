import jenkins.model.Jenkins
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm

def createUserIfMissing(realm, username, password) {
  try {
    realm.loadUserByUsername(username)
  } catch (Exception ignored) {
    realm.createAccount(username, password)
  }
}


// This script runs on Jenkins startup.
// Keep it for local/dev only. Avoid committing real credentials.

def j = Jenkins.get()

// Create a local user database (no self-signup).
def realm = new HudsonPrivateSecurityRealm(false)

// Create a user only if it does not already exist.
// (Jenkins stores users on disk; on subsequent startups this should be a no-op.)
createUserIfMissing(realm, "dev", "dev")
createUserIfMissing(realm, "dew", "dew")
createUserIfMissing(realm, "dex", "dex")

// Activate the local realm.
j.setSecurityRealm(realm)

// Authorization: logged-in users have full control; anonymous users have no read access.
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
j.setAuthorizationStrategy(strategy)

// Persist security configuration.
j.save()
