# Using st:adjunct to Load CSS and JavaScript Assets

## Overview

The `<st:adjunct>` tag in Jenkins Jelly files is the recommended way to load CSS and JavaScript assets. It provides automatic resource management, caching, and proper dependency handling.

## How st:adjunct Works

### File Resolution Order

When Jenkins encounters an `<st:adjunct>` tag, it searches for files in the following order:

1. **`.css`** - Cascading Style Sheets
2. **`.js`** - JavaScript files
3. **`.html`** - HTML fragments
4. **`.jelly`** - Jelly templates

Jenkins searches for these files in the `src/main/resources/` directory, matching the package structure of the adjunct name.

### Adjunct Naming Convention

The adjunct name follows Java package naming conventions:

```
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style" />
```

This resolves to:
```
src/main/resources/io/jenkins/plugins/openmfa/MFASetupAction/mfa-setup-style.css
```

### File Location Requirements

Assets must be placed in the **same directory** as the Jelly file that references them:

```
src/main/resources/
└── io/
    └── jenkins/
        └── plugins/
            └── openmfa/
                └── MFASetupAction/
                    ├── index.jelly          ← Jelly file
                    ├── mfa-setup-style.css  ← CSS asset
                    └── mfa-setup-script.js   ← JavaScript asset
```

## Implementation Example

### Jelly File (`index.jelly`)

```jelly
<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:st="jelly:stapler" xmlns:f="/lib/form" xmlns:l="/lib/layout">
  <l:layout title="${%title}" permission="${app.READ}">
    <!--
      When referencing frontend assets with <st:adjunct>, Jenkins first tries to resolve
      .css, then .js, .html, and .jelly extensions for the given name.
      If none of those files are present for a given adjunct path, a NoSuchAdjunctException occurs.
      The adjunct references below match the available .css and .js assets from your context
      and will not trigger an error.
    -->
    <st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style" />
    <st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-script" />
    <l:main-panel>
      <!-- Your page content here -->
    </l:main-panel>
  </l:layout>
</j:jelly>
```

### CSS File (`mfa-setup-style.css`)

```css
.mfa-container {
  max-width: 640px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.mfa-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
}
```

### JavaScript File (`mfa-setup-script.js`)

```javascript
function copySecret(button) {
  const input = button.previousElementSibling;
  const secret = input.value;
  // ... implementation
}
```

## Key Benefits

1. **Automatic Resource Management**: Jenkins handles caching, versioning, and dependency resolution
2. **Proper Loading Order**: CSS loads before JavaScript automatically
3. **No Manual Path Management**: No need to construct `${resURL}` or `${rootURL}` paths
4. **Type Safety**: Missing files throw `NoSuchAdjunctException` at build/runtime
5. **Consistent with Jenkins Patterns**: Follows Jenkins plugin development best practices

## Common Pitfalls

### Pitfall 1: Wrong File Location

**❌ Incorrect**: Placing assets in `src/main/webapp/`
```jelly
<!-- This won't work with st:adjunct -->
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style" />
```
Files in `webapp/` are served as static resources but cannot be loaded via `st:adjunct`.

**✅ Correct**: Place assets in `src/main/resources/` matching the package structure

### Pitfall 2: Mismatched Adjunct Name

**❌ Incorrect**: Adjunct name doesn't match file location
```jelly
<st:adjunct includes="mfa-setup-style" />
<!-- Looks for: src/main/resources/mfa-setup-style.css -->
```

**✅ Correct**: Use full qualified name matching package structure
```jelly
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style" />
<!-- Looks for: src/main/resources/io/jenkins/plugins/openmfa/MFASetupAction/mfa-setup-style.css -->
```

### Pitfall 3: Missing File Extension

**❌ Incorrect**: Including extension in adjunct name
```jelly
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style.css" />
```

**✅ Correct**: Omit extension (Jenkins adds it automatically)
```jelly
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style" />
```

### Pitfall 4: Using Script Tags Instead

**❌ Incorrect**: Manual script tag with resource URL
```jelly
<script src="${resURL}/plugin/openmfa-plugin/js/mfa-setup.js"></script>
```

**✅ Correct**: Use `st:adjunct` for resources in `src/main/resources/`
```jelly
<st:adjunct includes="io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-script" />
```

**Note**: Script tags with `${resURL}` are only needed for files in `src/main/webapp/`, which are served as static resources but don't benefit from adjunct management.

## File Naming Best Practices

1. **Use descriptive suffixes**: `-style.css`, `-script.js` to clearly identify file types
2. **Match adjunct names**: Keep adjunct name and filename consistent (minus extension)
3. **Avoid conflicts**: Use unique names within the same package directory

## Error Handling

### NoSuchAdjunctException

If Jenkins cannot find a matching file for an adjunct reference, it throws:

```
org.kohsuke.stapler.NoSuchAdjunctException: No such adjunct 'io.jenkins.plugins.openmfa.MFASetupAction.mfa-setup-style'
```

**Common causes**:
- File doesn't exist at the expected location
- File extension doesn't match (e.g., `.txt` instead of `.css`)
- Package path in adjunct name doesn't match directory structure
- File is in `webapp/` instead of `resources/`

## When to Use st:adjunct vs Script Tags

### Use `st:adjunct` when:
- ✅ Files are in `src/main/resources/` matching package structure
- ✅ You want automatic caching and dependency management
- ✅ Files are specific to a particular Jelly view/action
- ✅ Following Jenkins plugin best practices

### Use `<script>` tags when:
- ✅ Files are in `src/main/webapp/` (static resources)
- ✅ Files are shared across multiple plugins/pages
- ✅ You need explicit control over loading order
- ✅ Files are third-party libraries

## Related Files

- `src/main/resources/io/jenkins/plugins/openmfa/MFASetupAction/index.jelly` - Example Jelly file using adjuncts
- `src/main/resources/io/jenkins/plugins/openmfa/MFASetupAction/mfa-setup-style.css` - CSS asset loaded via adjunct
- `src/main/resources/io/jenkins/plugins/openmfa/MFASetupAction/mfa-setup-script.js` - JavaScript asset loaded via adjunct

## References

- [Jenkins Stapler Framework Documentation](https://stapler.kohsuke.org/)
- [Jenkins Plugin Development Guide](https://www.jenkins.io/doc/developer/plugin-development/)
- [Stapler Adjunct API](https://javadoc.jenkins.io/stapler/org/kohsuke/stapler/Stapler.html#adjunct-java.lang.String-)
