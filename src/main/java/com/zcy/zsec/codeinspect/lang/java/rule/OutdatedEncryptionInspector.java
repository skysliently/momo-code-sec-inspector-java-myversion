/*
 * Copyright 2020 momosecurity.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.*;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.java.util.ZSecExpressionUtils;
import org.jetbrains.annotations.NotNull;

/**
 * 在CipherWeaknessInspector中已实现
 * DES / 3DES(DESede) 为过时的加密标准
 *
 * 检查如下内容
 * javax.crypto.Cipher.getInstance
 * <li><tt>DES/CBC/NoPadding</tt> (56)</li>
 * <li><tt>DES/CBC/PKCS5Padding</tt> (56)</li>
 * <li><tt>DES/ECB/NoPadding</tt> (56)</li>
 * <li><tt>DES/ECB/PKCS5Padding</tt> (56)</li>
 * <li><tt>DESede/CBC/NoPadding</tt> (168)</li>
 * <li><tt>DESede/CBC/PKCS5Padding</tt> (168)</li>
 * <li><tt>DESede/ECB/NoPadding</tt> (168)</li>
 * <li><tt>DESede/ECB/PKCS5Padding</tt> (168)</li>
 *
 * ref:
 * https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard
 *
 * 主要针对Cipher，追加AES/ECB风险提示
 *
 */
public class OutdatedEncryptionInspector extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("outdated.encryption.inspector.msg");
    public static final String AES_ECB_MESSAGE = InspectionBundle.message("outdated.encryption.inspector.aesecb.msg");

    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                if (ZSecExpressionUtils.hasFullQualifiedName(expression, "javax.crypto.Cipher", "getInstance")) {
                    PsiExpressionList argList = expression.getArgumentList();
                    PsiExpression[] args = argList.getExpressions();
                    if (args.length > 0 && args[0] instanceof PsiLiteralExpression) {
                        String trans = ZSecExpressionUtils.getLiteralInnerText(args[0]);
                        if (null != trans && trans.startsWith("DES")) {
                            holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        }
                        else if (null != trans && trans.startsWith("AES/ECB"))
                            holder.registerProblem(expression, AES_ECB_MESSAGE, ProblemHighlightType.WARNING);
                    }
                }
            }
        };
    }
}
