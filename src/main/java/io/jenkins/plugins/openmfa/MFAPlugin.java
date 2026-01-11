package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.init.Terminator;
import hudson.util.PluginServletFilter;
import lombok.NoArgsConstructor;

@Extension
@NoArgsConstructor
public class MFAPlugin {

  @Initializer(after = InitMilestone.STARTED)
  public static void add() throws Exception {
    PluginServletFilter.addFilter(new MFAFilter());
  }

  @Terminator
  public static void remove() throws Exception {
    PluginServletFilter.removeFilter(new MFAFilter());
  }

}
