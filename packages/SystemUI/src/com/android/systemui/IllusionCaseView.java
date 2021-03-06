/*
 * Copyright (C) 2013 The Android Open Source Project
 * Copyright (C) 2013 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.systemui;

import com.android.systemui.DessertCaseView;
import com.android.systemui.R;

import android.content.Context;
import android.util.AttributeSet;

public class IllusionCaseView extends DessertCaseView {
    private static final int[] PASTRIES = {
            R.drawable.dessert_illusion
    };

    private static final int[] RARE_PASTRIES = {
            R.drawable.dessert_illusion2
    };

    private static final int[] XRARE_PASTRIES = {
            R.drawable.dessert_illusion3
    };

    private static final int[] XXRARE_PASTRIES = {
            R.drawable.dessert_illusion4
    };

    private static final int NUM_PASTRIES = PASTRIES.length + RARE_PASTRIES.length
            + XRARE_PASTRIES.length + XXRARE_PASTRIES.length;

    public IllusionCaseView(Context context) {
        super(context, null);
    }

    public IllusionCaseView(Context context, AttributeSet attrs) {
        super(context, attrs, 0);
    }

    public IllusionCaseView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    @Override
    protected int[] getPastries() {
        return PASTRIES;
    }

    @Override
    protected int[] getRarePastries() {
        return RARE_PASTRIES;
    };

    @Override
    protected int[] getXRarePastries() {
        return XRARE_PASTRIES;
    }

    @Override
    protected int[] getXXRarePastries() {
        return XXRARE_PASTRIES;
    }

    @Override
    protected int getNumPastries() {
        return NUM_PASTRIES;
    }
}
