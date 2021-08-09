/*
 * 复制自MomoBaseLocalInspectionTool
 */
package com.zcy.zsec.codeinspect.lang;

import com.immomo.momosec.lang.java.utils.MoExpressionUtils;
import com.intellij.codeInspection.AbstractBaseJavaLocalInspectionTool;
import com.intellij.psi.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public abstract class ZSecBaseLocalInspectionTool extends AbstractBaseJavaLocalInspectionTool {

    public enum VulnElemType {
        ASSIGNMENT_EXPRESSION,
        LOCAL_VARIABLE,
        CLASS_FIELD
    }

    /**
     * 本方法针对可利用安全设置修复的漏洞，例如：
     * DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
     * dbf.setFeature(...);
     * 检查变量 (如dbf) 所在 scope 是否满足 visitor 的要求。
     * 若变量定义与使用分离(如dbf定义为类成员，但初始化在某一方法内)，则assignElem指初始化元素，resolvedElem为定义元素
     *
     * (1) 对于变量在方法/静态块/构造块内初始化， scope 为当前方法/静态块/构造块
     * (2) 对于变量是类成员变量，并且在定义时赋值，有两种情况
     * (2.1) 对于 static 成员变量，检查该类的静态块是否满足 visitor 要求
     * (2.2) 对于非 static 成员变量，检查该类的构造块是否满足 visitor 要求
     * @param assignElem  PsiElement
     * @param resolvedElem PsiElement
     * @param visitor PsiElementVisitor
     * @return boolean
     */
    protected boolean checkVariableUseFix(@Nullable PsiElement assignElem, @Nullable PsiElement resolvedElem, @NotNull ZSecBaseFixElementWalkingVisitor visitor) {
        PsiMethod method = MoExpressionUtils.getParentOfMethod(assignElem);
        if (method != null) {
//            触发DisableEntityElementVisitor中重写的visitElement方法
            method.accept(visitor);
            return visitor.isFix();
        }

        PsiClassInitializer initializer = MoExpressionUtils.getParentOfClassInitializer(assignElem);
        if (initializer != null) {
//            触发DisableEntityElementVisitor中重写的visitElement方法
            initializer.accept(visitor);
            return visitor.isFix();
        }

        if (resolvedElem instanceof PsiField) {
            PsiField field = (PsiField)resolvedElem;
            if (field.hasModifierProperty(PsiModifier.STATIC)) {
                return checkStaticInitializersHasFix((PsiClass)field.getParent(), visitor);
            } else {
                return checkConstructorHasFix((PsiClass)field.getParent(), visitor);
            }
        }

        return false;
    }

    private boolean checkConstructorHasFix(PsiClass aClass, ZSecBaseFixElementWalkingVisitor visitor) {
        PsiClassInitializer[] initializers = aClass.getInitializers();
        for (PsiClassInitializer initializer : initializers) {
            if (!initializer.hasModifierProperty(PsiModifier.STATIC)) {
//            触发DisableEntityElementVisitor中重写的visitElement方法
                initializer.accept(visitor);
                if (visitor.isFix()) {
                    return true;
                }
            }
        }

        PsiMethod[] constructors = aClass.getConstructors();
        for(PsiMethod constructor : constructors) {
            constructor.accept(visitor);
            if(visitor.isFix()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkStaticInitializersHasFix(PsiClass aClass, ZSecBaseFixElementWalkingVisitor visitor) {
        PsiClassInitializer[] initializers = aClass.getInitializers();
        for(PsiClassInitializer initializer : initializers) {
            if (initializer.hasModifierProperty(PsiModifier.STATIC)) {
                initializer.accept(visitor);
                if (visitor.isFix()) {
                    return true;
                }
            }
        }
        return false;
    }

}
