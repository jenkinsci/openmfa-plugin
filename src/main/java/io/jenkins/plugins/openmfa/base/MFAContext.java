package io.jenkins.plugins.openmfa.base;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import lombok.extern.java.Log;

/**
 * Factory class for managing and providing MFA service instances. Implements
 * singleton pattern with service registry for dependency injection.
 */
@Log
public class MFAContext {

    private static final String BASE_PACKAGE = "io.jenkins.plugins.openmfa";
    private static final MFAContext INSTANCE;

    // Service registry: maps service class to its singleton instance
    private final Map<Class<?>, Object> services = new ConcurrentHashMap<>();

    // Flag to track if services have been initialized
    private boolean initialized = false;

    static {
        try {
            INSTANCE = new MFAContext();
            INSTANCE.initialize(BASE_PACKAGE);
        } catch (Exception e) {
            throw new MFAException("Exception while creating singleton instance", e);
        }
    }

    /**
     * Private constructor for singleton pattern.
     */
    private MFAContext() {}

    /**
     * Gets the singleton instance of MFAContext.
     *
     * @return the singleton MFAContext instance
     */
    public static MFAContext i() {
        return INSTANCE;
    }

    /**
     * Initializes the service context by scanning and registering all @Service
     * annotated classes. This method should be called once during plugin
     * initialization.
     *
     * @param packageName the base package to scan for services (e.g.,
     *                    "io.jenkins.plugins.openmfa")
     */
    public void initialize(String packageName) {
        if (initialized) {
            log.info("MFAContext already initialized");
            return;
        }

        try {
            log.info("Initializing MFAContext and scanning for services in package: " + packageName);
            List<Class<?>> serviceClasses = scanForServices(packageName);

            for (Class<?> serviceClass : serviceClasses) {
                if (!hasService(serviceClass)) {
                    Object instance = createServiceInstance(serviceClass);
                    services.put(serviceClass, instance);
                    log.info("Auto-registered service: " + serviceClass.getName());
                }
            }

            // Inject dependencies into all registered services
            injectDependencies();

            initialized = true;
            log.info("MFAContext init complete. Registered " + services.size() + " services.");
        } catch (Exception e) {
            throw new MFAException("Failed to initialize MFAContext", e);
        }
    }

    /**
     * Scans the specified package for classes annotated with @Service.
     *
     * @param packageName the package to scan
     * @return list of service classes found
     */
    private List<Class<?>> scanForServices(String packageName) {
        List<Class<?>> serviceClasses = new ArrayList<>();

        try {
            String path = packageName.replace('.', '/');
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            URL resource = classLoader.getResource(path);

            if (resource == null) {
                log.warning("Package not found: " + packageName);
                return serviceClasses;
            }

            File directory = new File(resource.getFile());
            if (directory.exists()) {
                scanDirectory(directory, packageName, serviceClasses);
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error scanning package: " + packageName, e);
        }

        return serviceClasses;
    }

    /**
     * Recursively scans a directory for service classes.
     */
    private void scanDirectory(File directory, String packageName, List<Class<?>> serviceClasses) {
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectory(file, packageName + "." + file.getName(), serviceClasses);
            } else if (file.getName().endsWith(".class")) {
                String className = packageName
                        + '.'
                        + file.getName().substring(0, file.getName().length() - 6);
                try {
                    Class<?> clazz = Class.forName(className);
                    if (clazz.isAnnotationPresent(Service.class)) {
                        serviceClasses.add(clazz);
                    }
                } catch (ClassNotFoundException e) {
                    log.log(Level.SEVERE, "Could not load class: " + className, e);
                }
            }
        }
    }

    /**
     * Creates a new instance of a service class.
     */
    private Object createServiceInstance(Class<?> serviceClass) {
        try {
            return serviceClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new MFAException("Failed to instantiate service: " + serviceClass.getName(), e);
        }
    }

    /**
     * Injects dependencies into all registered services. Scans for @Inject
     * annotated fields and populates them with service instances.
     */
    private void injectDependencies() {
        for (Object service : services.values()) {
            injectIntoObject(service);
        }
    }

    /**
     * Injects dependencies into a specific object.
     *
     * @param target the object to inject dependencies into
     */
    private void injectIntoObject(Object target) {
        if (target == null) {
            return;
        }

        Class<?> clazz = target.getClass();
        for (Field field : clazz.getDeclaredFields()) {
            if (field.isAnnotationPresent(Inject.class)) {
                try {
                    field.setAccessible(true);
                    Class<?> fieldType = field.getType();
                    Object dependency = getService(fieldType);
                    field.set(target, dependency);
                    log.fine("Injected " + fieldType.getSimpleName() + " into " + clazz.getSimpleName() + "."
                            + field.getName());
                } catch (Exception e) {
                    throw new MFAException("Failed to inject dependency into field: " + field.getName(), e);
                }
            }
        }
    }

    /**
     * Registers a service instance in the context.
     *
     * @param <T>          the type of the service
     * @param serviceClass the service class
     * @param instance     the service instance to register
     */
    public <T> void registerService(Class<T> serviceClass, T instance) {
        if (serviceClass == null || instance == null) {
            throw new IllegalArgumentException("Service class and instance cannot be null");
        }
        services.put(serviceClass, instance);

        // Inject dependencies into the newly registered service
        injectIntoObject(instance);

        log.info("Registered service: " + serviceClass.getName());
    }

    /**
     * Gets a service instance by its class type. If the service is not registered,
     * attempts to create and register it.
     *
     * @param <T>          the type of the service
     * @param serviceClass the service class to retrieve
     * @return the service instance
     * @throws RuntimeException if the service cannot be instantiated
     */
    @SuppressWarnings("unchecked")
    public <T> T getService(Class<T> serviceClass) {
        if (serviceClass == null) {
            throw new IllegalArgumentException("Service class cannot be null");
        }

        return (T) services.computeIfAbsent(serviceClass, clazz -> {
            try {
                // Check if the class is annotated with @Service
                if (!clazz.isAnnotationPresent(Service.class)) {
                    log.warning("Class " + clazz.getName() + " is not annotated with @Service");
                }

                T instance = serviceClass.getDeclaredConstructor().newInstance();
                log.info("Created and registered service: " + serviceClass.getName());
                return instance;
            } catch (Exception e) {
                throw new MFAException("Failed to instantiate service: " + serviceClass.getName(), e);
            }
        });
    }

    /**
     * Checks if a service is registered in the context.
     *
     * @param serviceClass the service class to check
     * @return true if the service is registered, false otherwise
     */
    public boolean hasService(Class<?> serviceClass) {
        return services.containsKey(serviceClass);
    }

    /**
     * Removes a service from the context.
     *
     * @param serviceClass the service class to remove
     */
    public void removeService(Class<?> serviceClass) {
        Object removed = services.remove(serviceClass);
        if (removed != null) {
            log.info("Removed service: " + serviceClass.getName());
        }
    }

    /**
     * Clears all registered services from the context.
     */
    public void clear() {
        services.clear();
        log.info("Cleared all services from MFAContext");
    }

    /**
     * Gets the number of registered services.
     *
     * @return the number of registered services
     */
    public int getServiceCount() {
        return services.size();
    }

    /**
     * Checks if the context has been initialized.
     *
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized;
    }
}
