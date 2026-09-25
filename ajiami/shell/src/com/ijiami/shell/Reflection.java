package com.ijiami.shell;

import java.lang.reflect.Field;

/** 反射小工具：真实壳大量使用反射隐藏调用目标，这里保持同样的风格。 */
public final class Reflection {

    private Reflection() {
    }

    public static Field fieldOf(Class<?> clazz, String name) throws NoSuchFieldException {
        Class<?> c = clazz;
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}
