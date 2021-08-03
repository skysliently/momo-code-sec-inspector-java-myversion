package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.JavaElementVisitor;
import com.intellij.psi.JavaTokenType;
import com.intellij.psi.PsiElementVisitor;
import com.intellij.psi.PsiLiteralExpression;
import com.intellij.psi.tree.IElementType;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import org.jetbrains.annotations.NotNull;


/**
 * 1025: IP地址硬编码；未修改
 *
 * ref: https://rules.sonarsource.com/java/type/Security%20Hotspot/RSPEC-1313
 */
public class HardcodedIp extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("hardcoded.ip.msg");

    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitLiteralExpression(PsiLiteralExpression expression) {
                IElementType type = expression.getFirstChild().getNode().getElementType();
                if (type == JavaTokenType.STRING_LITERAL) {
                    Object v = expression.getValue();
                    if (v != null && isSensitiveIp(v.toString())) {
                        holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                    }
                }
            }
        };
    }

    private static boolean isSensitiveIp(String ip) {
        //判断是否是7-15位之间（0.0.0.0-255.255.255.255.255）
        if (ip.length()<7||ip.length()>15) {
            return false;
        }

        //判断是否能以小数点分成四段
        String[] ipArray = ip.split("\\.");
        if (ipArray.length != 4) {
            return false;
        }

        for (int i = 0; i < ipArray.length; i++) {
            //判断每段是否都是数字
            try {
                int number = Integer.parseInt(ipArray[i]);
                //判断每段数字是否都在0-255之间
                if (number < 0 || number > 255) {
                    return false;
                }

                // 忽略 127.0.0.1/8
                if (i == 0 && number == 127) {
                    return false;
                }
            } catch (Exception e) {
                return false;
            }
        }


        if ("255.255.255.255".equals(ip) ||  // 忽略 255.255.255.255
            "0.0.0.0".equals(ip) ||  // 忽略 0.0.0.0
            ip.startsWith("2.5.")  // // 忽略 2.5.x.x (OID)
        ) {
            return false;
        }

        return true;
    }
}
