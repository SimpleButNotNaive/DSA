import random
from DSA import modular_exponent

p = 0x008746338ba0d0b67ec6dde878f14d624dfe86a4663aaf170208b02b020c09199af1dbaaf0ba5a70d52b3eb715f775b0989ff176d1d6c680042dab48d35d802c598036280c559ffb59ea4c82c01fae4a227847cb715e03511602f7dedd0d0f1556c5e63c9b181a4a7ffb1416a3d6ef69cb9b413746aab5e259c3b12bec3244a7e09f6718ecb721c528020a9ae09568f461512c526593563fad544106fb5fa90922aef456a0f110ccab7628d793ca3c5f6a4c6e22ee05227e1d3c395f99f52418c5dfdee1442d0aa3ca1e9154cae569c25497c3445f2bed1e8de3cada7e2f1825d7341e591234df4053ca5b33c92e3217967ca00211b68c1b0aafa5152b84557a81
q = 0x00bdd727428445e6e4ad64978a4184de1f28ab3f298e79f11147bee060150040e1
g = 0x75fd519cb49bcfd504dc7f8bfb100511dee71335ba07d7bf85e0b602441b121fc1b537f29b941254f85703d2aa41e2cf400e3be7d952ad9a32f461174873034631295c2bc86d5134779358e8f4c6d54e591edc645dbd389088f9a7dfa3927fbeedce1bc57fa1e6dd3908daac26914ead4f40e8acab8b57a303d1970a06393789c56decbb504f7ae3d9f8e2cd1850b9e77d4aa64f49218fd0f6c24ccb5aa6af9d97e4d041b0676dda90dfbba0177df89b730ab1b8db5ef19ebd2fed52a790826fc507647576bebed69e5a8a11ec25f89d445b56b738d2a7f713d74527a4e6ed99af43ebcdb2cfe2ccaee76fd543ea429ec6402c273b030a63e6a686b2d299d8d7
message = "SchoolofDataandComputerScience,Sunyat-senUniversity"

alpha = 2541552517763577372793239728936534558202546009046275857462373456857344471448408479565430518741449892006930156192454581605243733577213525797982971059356035002536348795486708026315013686521629286777266488528180605617029433138306532641032902518459578583539259775118967654144160939691821720580626671953415807293448441909464983260366062539587208608800409049276438430975540493720251072944426519326454877443558835237853754174785462628763612303591541702879474921244821309736104307585621949524780073133578428180476178108488443008506098161092886609714126356373636548692696101211147053480002903841833245957420445281557281242329
a = 20361416670428666585809712321893291403127918935731055094356469787628752935965
beta = 6045630225547951285117167448605323485740035169943709784317088365071673619647106853481981823089924297025049783253832293046851442145404674532703442189804478065260666011323709965282536379709614394009886976948597412068245902825064017840313435656507025834164351486860460129668866703619245581585393698974031961831702650657238669168075000261141910803281258872572282236762437059851061521866254993801696455443707401608647183447952109201709175009425175037084792433807991755892875366144374104478111685128912698020690693118595124045277894580953679631008568147728695754466789105659494154490208780576838980386930630538680267911434

if __name__ == "__main__":
    print(modular_exponent(g, (p -1) // q, p))
    print(modular_exponent(alpha, q, p))
