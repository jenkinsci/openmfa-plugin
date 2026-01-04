package io.jenkins.plugins.openmfa.base;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark classes as services for dependency injection.
 * Services annotated with @Service will be managed by the service container.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Service {
    /**
     * Optional name/identifier for the service.
     * If not specified, the class name will be used.
     */
    String value() default "";
}
