package com.zcy.zsec.codeinspect.lang.java.util;

import com.intellij.psi.*;
import com.intellij.psi.util.PsiUtil;
import com.intellij.psi.util.TypeConversionUtil;
import com.siyeh.ig.psiutils.ExpressionUtils;
import com.siyeh.ig.psiutils.MethodCallUtils;
import org.jetbrains.annotations.Nullable;

public class ZSecExpressionUtils {

    /**
     * 获取文本节点的内容
     * @param expression PsiExpression
     * @return String | null
     */
    @Nullable
    public static String getLiteralInnerText(@Nullable PsiExpression expression) {
        PsiLiteralExpression literal = ExpressionUtils.getLiteral(expression);
        if (literal != null) {
            Object value = literal.getValue();
            if (value != null)
                return value.toString();
        }
        return null;
    }

    /**
     * 判断方法名是否与methodName相同并且方法是否在qualifiedName类中
     * @param methodCall 方法调用表达式
     * @param qualifiedName 完整类名
     * @param methodName 方法名
     * @return boolean
     */
    public static boolean hasFullQualifiedName(PsiMethodCallExpression methodCall, String qualifiedName, String methodName) {
        String methodCallName = MethodCallUtils.getMethodName(methodCall);
        if (!methodName.equals(methodCallName)) {
            return false;
        }

        PsiMethod method = methodCall.resolveMethod();
        if (method == null) { return false; }

        PsiClass containingClass = method.getContainingClass();
        if (containingClass == null) { return false; }

        return qualifiedName.equals(containingClass.getQualifiedName());
    }

    /**
     * 将表达式尝试转换为文本内容
     * (1) 文本节点解析
     * (2) 基础类型 / 枚举类型
     * (3) field 字段
     * @param expression PsiExpression
     * @param force boolean             强制转换为表达式字面值
     * @return String
     */
    @Nullable
    public static String getText(@Nullable PsiExpression expression, boolean force) {
        if (expression == null) {
            return null;
        }

        String value = getLiteralInnerText(expression);

        if (value == null && (
                TypeConversionUtil.isPrimitiveAndNotNull(expression.getType()) ||
                        PsiUtil.isConstantExpression(expression) &&
                                !(expression instanceof PsiPolyadicExpression)
        )) {
            value = expression.getText();
        }

        if (value == null && expression instanceof PsiReferenceExpression) {
            PsiElement resolve = ((PsiReferenceExpression) expression).resolve();
            if (resolve instanceof PsiField) {
                // 对于 field 可不区分force，field值不是Text时，直接用field变量名
                PsiExpression initializer = ((PsiField) resolve).getInitializer();
                if (initializer != null) {
                    value = getText(initializer, false);
                }
                if (value == null) {
                    value = ((PsiField) resolve).getName();
                }
            }
        }

        if (value == null && expression instanceof PsiPolyadicExpression) {
            StringBuilder sb = new StringBuilder();
            for(PsiExpression operand : ((PsiPolyadicExpression) expression).getOperands()) {
                String text = getText(operand, force);
                if (text == null) {
                    sb.setLength(0);
                    break;
                }
                sb.append(text);
            }
            if (sb.length() != 0) {
                value = sb.toString();
            }
        }

        if (force && value == null) {
            value = expression.getText();
        }
        return value;
    }
}
