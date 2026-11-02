# الإصدار 1.8.0 — التماثل الداخلي والتقطيع، على `1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa`

كل رقم هنا من تشغيل حقيقي محفوظ في هذا المجلد. لم يتغير أي استنتاج من 1.7.0،
وهذا مقصود: الإصدار الجديد يتحقّق من حساب ويصف بنية، ولا يدّعي كشفاً.

## 1. ما أُضيف

| القدرة | الأمر | ما تُثبته |
| --- | --- | --- |
| تماثل secp256k1 الداخلي (GLV) | `glv-check` | حساب صحيح، لا معلومة عن مفتاح بعينه |
| تقطيع الكلمات والطيّ بـXOR | `analyze-segments` | لا بنية على مستوى الكلمة في الحمولة |
| الربط في التقارير القائمة | `dissect-public-key` / `dissect-address` / `--segments` | نفس الحساب على ثلاث واجهات |

## 2. GLV على المولّد `G`

```text
phi(P)             02bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb
phi^2(P)           02c994b69768832bcbff5e9ab39ae8d1d3763bbf1e531bed98fe51de5ee84f50fb
lambda * P         02bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb
all checks         pass        (8 من 8)
three-torsion sum  O
```

**الوسم مقصود:** «خاصية منحنى، لا خاصية مفتاح». كل مفتاح صالح ينجح في الفحوص
الثمانية. الأثر العملي: عامل 2 في ثابت الهجوم، أي 2^128 تصبح نحو 2^127 عملية.
**الأُسّ لا يتحرك.**

## 3. تقطيع حمولة الهدف

```text
Width   Segments  Fold XOR            Complete  Reading
------  --------  ------------------  --------  ---------
8-bit   20        0xf6                yes       no signal
16-bit  10        0xe513              yes       no signal
32-bit  5         0xd1f934ea          yes       no signal
64-bit  3         0x3bf37446ea0a40ac  no        no signal
  byte reversal: not a palindrome; balance p=0.2059
```

القواعد الثلاث: الطيّة غير الصفرية هي النتيجة الطبيعية وتُطبع مع ذلك؛ الطيّة
الصفرية مصادفة باحتمال `2^-العرض`؛ والذيل القصير يُوسم ناقصاً ولا يُبطَّن بصمت.

## 4. الضبط الموجب

لكي لا يكون «no signal» كلاماً فارغاً، جرّب الأمر على بيانات فيها بنية فعلية:

```bash
binarycryptolab analyze-segments deadbeefdeadbeef --widths 32
```

النتيجة `fold XOR = 0x00000000` مع حكم «worth inspecting». الأداة تُصدر الإشارة
عندما توجد فعلاً، ولهذا يحمل غيابها معنى.

## 5. ما لم يتغير

| البند | القيمة |
| --- | --- |
| النوع والحمولة | P2PKH، `70542a0b4e6776be4ba75e4d975ec8de3333fecc` |
| checksum | `e5fae25f` صالح |
| اختبارات العشوائية | 8 من 8 ناجحة |
| كلفة السلسلة العكسية | 2^288 |
| الاستعادة من عنوان | مستحيلة، مقيسة لا مفترضة |

## 6. إعادة الإنتاج

```bash
T=1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa
binarycryptolab dissect-address $T
binarycryptolab analyze-segments 70542a0b4e6776be4ba75e4d975ec8de3333fecc
binarycryptolab glv-check 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
binarycryptolab dissect-public-key --public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

## 7. الملفات

| الملف | المحتوى |
| --- | --- |
| `dissect.txt` / `dissect.json` | تفكيك العنوان + قسم التقطيع |
| `segments.txt` / `segments.json` | تقرير التقطيع الكامل للحمولة |
| `glv.txt` | الفحوص الثمانية |
| `public_key_dissect.txt` | تفكيك المفتاح مع قسم GLV |
| `report_ar.md` | هذا التقرير |
