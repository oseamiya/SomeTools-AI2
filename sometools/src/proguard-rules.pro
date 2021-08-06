# Add any ProGuard configurations specific to this
# extension here.

-keep public class tech.oseamiya.sometools.Sometools {
    public *;
 }
-keeppackagenames gnu.kawa**, gnu.expr**

-optimizationpasses 4
-allowaccessmodification
-mergeinterfacesaggressively

-repackageclasses 'tech/oseamiya/sometools/repack'
-flattenpackagehierarchy
-dontpreverify
