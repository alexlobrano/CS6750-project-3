# B.py

# Implement the Proof-of-Work (PoW) construction based on hash puzzles discussed in class:
# - SolvePuzzle(x, n): Find a value s in {0, 1}^n such that H(s, x) starts with n zero bits.
# - VerPuzzle(s, x, n): Test if H(s, x) starts with n zero bits.
# Use the SHA-256 hash function. Vary the parameter n from 5 to 25 (at steps of 5) and record the
# timing it takes to solve the puzzle.

from Alex_Lobrano_implementation import *

filename = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename + '.txt', 'w')

total_users = 10
hardcoded = [(13281310054460396188358823510902093259883930848501257339549719515159467176827991004659624544985959490721499400409693406293953737683048770954620124130846929409518470257772567858472421688796271114776141057181948727959776770767597954426266902501415374564030185870143937292191628923535577701117789072408621351072508096471108480085508535678447018050524860398119668440453025596320984405137454542053044632841295360852413904886927959747804588446796500549307266988138753456122751392196033086286032941988347253805906875527369023949018928942398849104926340777643190531394909109573871052343831750876935203771219236805287225010921L, (19625301651662850402344408922099124895091782303032279855828179294881642704850905530231767592199780693862169443670429390228309830773933625831918567089856765736749455046644312600691397019410538482531301001825047437817709466991164092018159488763662848138846565714110491307094823733535889807774560606170271884550755385650153650683767207576204333693668546326660466697237618148008678522469349568758101477196113881006267411977842026303258392150931417461403491344179216287056898963883586372743466714184526472538007541966061016834872307978898551307735517252267347421177727453327043802098212340950422005220325834953306886085879L, 10600850086265361703453154282676694162425568544513751764926829052798790248989638786721978887210099307917313508191971986360783823647256959864502128786777958233828903922124337014565095928956159675217844324022419958142701925025258106283262078339278817318486085204273815351419201946194179324259324050771537347622362064003802476907067530704503347530573602938243564878875777382358653615658121600435354334401670091377477056381036875700576519217976762622274612770942746050060943033924146638762862084850151270951262654501179265333750809402865440749176283736031662194621097621803144676379910112282935519663972219245806552337561L)), 
(14538744759097377001969408181809135188030182231034937848175515308209732825159332961186268295780025195288150405969577487327579782740329675786711701655274729603816533274634127383809430544466747564038215727202229045780788777028005332388195036547702930469268079618274996043613319719261724732701989725508808649190076558305794261592193730082818413458446011205995226306014173867796582851745302080453396310786865500544850612611899207561030855473732345854609401818336712323756411135529492059331583467548301999608738917340547196899552189293119434033050770411027918315204338385899250875043456933553564826546069416851759842771277L, (19871618071290754032188333824948647373655655797968522612388625137931200834506340857947415223861029699228862809240702808183711675994512687271624462079177687946164986199844785376164908785000805411143536676708905304097674226672558259185142431380260766981975393204238454377437560144390981331741961318170912911163513582417276336261536749314760365641007896793271832720368784679204763435556881843545161537186848482295616472863315738075731372580962238800301377263149629137718666931104377214530085854210015406735570961006620679276664386915636428168994165615510743048363326925153659135224369210882065025814600126241543358189261L, 2184169828747081289570086288964218141521760169766072417039918529492356773744860771162194635257245445105567841276497177089115153622959756447389387427077028626612160933517057620550968771888232430984879636771174529264054374250718377355765287619530536862934000320111466978542612951314941485880141235500165900411681943408314425266975210309928523911414055953252520176762602297872675685220046798232534785782497529634090482792860606145822637211306671648230335181645491712534151813130032741415906751749935095364673149931259080182642677501176529031266066922694429760480357418416073513584648722779635747309891206923309219328213L)), 
(19661502660462288153592021604236684510357385709385868672418067121608656071321038282122269546675864329215359557149355595660554657026390615287909523115970090384227552291345345201363150594803817288895115121736454138017454000909345626910627867035241345399870616747756870535474568151635188287319797829901390194403807950349077764445193008673781612165302636787567153309671133149157539186046730818215440336753797638883632612364844439200155691276238493108065276026952184296020002874063407713689386194481432766368385741528805898008020560394122288181138731732782331527230970925868407063710179056899720711190857915595798389009931L, (19685447669643380256891109590492485110081459662117061282528816693448862331397342122900923102792516677862756002892777244491488984320279769643043583595470105293930762500434186064765069400591752014980071761027086991895196808247433977897748769738689274260124837141413299920071109283742455608750624627154444353962058154721949525293185218079526640020980349861381261376368645290179145230459416908631608097492280603678848139142818785818450924166936372661558201914361929618019312733805254314568338664157875108808808631697543162864625022495707173460819153693496991647353439969179958644373169913233736695589942015488548976468429L, 2395804783170394689624957974896309976779385510741016829999226239059941027701129887808629140261529206093203834396388451242519344635399417427283441381790873510547350254425923891931409599978649315348371126650512406398503926516651212643200646413248011952272238782681386163262508633664982689440893317939592408977893515176211386720648270255295654847443945397415333656436451060492759496996624790930511493562132100074013947679530444677686337616708969262149365242780690464543014284054458167242714554119137903207047359575463684317773255673865395054925905382007676126154025646714276074683396069167960077141985965586095468857251L)), 
(17185312180246292671853464290295886321876675491695189893472234517627489860894776886938257564955070851676200966414916373232697797969097427051760034262082871433269051766819550078989128981782302320535244987387790819527828246962496309079940384078290168938549106917140548688035896344059009753439895315035862672628024777106949665252606166521613971487731803679857001729730024759344906113043040764464324386660965963339715161432381482104410254562248121984301776711914975759346359216375208307231029828024575801476369432998457602462426772904560980798644738934005543968980079688638380743232246073389927805214715209541952599410799L, (15615290475798608664465029449265862339466858921620352673233112018624828625316106068438512138080133819766683097341714419272863440900045121794318708505940053552838099652722735770671731299313975653191279221091089087519676608687872665886542762981595209435853587869973722308005039326924679583621734378115779568139007860132344606721332218975215754133974179541199820169309363976119618162874741405233534246042826161679187109434796175423464751871413014910036107220106893916015892147693241712623085830799192447674049788297469574550293992074636676061977268157881020621177122228543593420144723562313446821623648326389494319366267L, 5094912648649444507591540226835763825781915901897059883537555038222992769369649984130965340739437530323000027447139856836565227055175842846938656001400803606530862132675691615155350869437212795961164433897960610479770574895636631851025968923387161115151953535933732100197373489317426176550479011163841699735149816735214180172801417367482266498861639466860248386076304452149930493869871924937027496632699162100064056613352402527194140065665418767407544575675896834949286795532407956137729257359043577047875355600541813909453823292644703358554629794830387633707269914737904295196530689381202936819808384580257458908599L)), 
(13285825591317536363898015986403154936627332278926731111774101911355852413009181679518806380294418618115897250982694933586843015272660676573000596745568803999223919539877633728808571508544588173576222658963528145027453735310668253922062518286904322158485990216654461202028342402152743000662802146049555794051093877076682319233296049521782155831619675296108186267741319848041193177511143450644025564852202182529405381324770596552852363679290248446131022146367898400866698740904070334726527851964123704965810594040424573040305450203835947178330279598354524766223039979109571727606460367173502706595904552258286421724245L, (11301299718660356663288267882961575072460474491823162833210770563197275928822414515448840979520368936214541065423539916704904692007946176226669976701073334849390665471014327623430486401697524513624003757996616503267316521612980111283249757174029890418256386076483897165398115863069299157309484963708550967465485133099643147076523700416932165149736653753591303127734534102994962162045486617536817552123483452433524930641456665368129943042628767906249554282021211707908444160497747300345981552871356407378996040414467686522705782670169035255370428106919937850540192579991802446232021155161881996882383873815247156699791L, 9806364014434284193225342232918377067850582183615566130977323844604766596649223466918303913883646108825993898331344838053792194314337055584553967859623787224012509341493815105950463756766376224229655923519116246945702483000442152017849475313424714686866725448112151341511315546683134316911488874081490695440364946593901377037684921870557468443303567549946423951758089476465118966636908999808840969438738582168966159438581596490211937260465519956429755938397791875993855109496780313678968329214344383714559554122893601242296119279568555379418410285496252006145054617936769530652433612320724422626095206740846530311405L)),
(18471893019021435354513092083073582818833975122217363584945519971357718951487723714954737617837327000233440930355762817214446289369288667424152371426941149392647929312162849406046874629290587174879245225260767864902322114370178820307006479234706151749806324094019545868392510246551879999901211776061550057669789883021634637183251532308947817392175171062703598619715847199909523740036621728843746066841023846053713167518779112177460116967881116055415245026749057242318795178010199567638482965446611482923895704315023369145741966431240620417217206385229330361037104907835762748402753146740510179740344363732886382872339L, (15532121519931113774374337572898480044602383083116752524942507818312767232587693345698577072185805360183589684521019252082334136347488250753021878621679482808880928897623484044382395784661353990812411364040721637129302062496381405985675542426401322738685953058675302245054083397366140204785714609826030333837437426589476740767167987359644458275007385979371298114078388644043656078022979470244262136167520648556662023427229984480196439309598990550599195435236087412771234229910440269531435049985164307389026377547612904747629342339988515834851977968470608553637462684093665468316740269616987085923873901877634409743769L, 3228541389100852288274484168549824734451019109911490100766176905087887410501383751036787901168608748165054484902137691111219853251939729753301975529898151753232467562011739631312313161438780254492117090362511834706165840983845388639504694746185520655613238865406696261819184255230441823267580871115158983583265643820332944554199583135552449396654280972774638928308856401581775413497874235400677629870763162566834019779706655812139515966244308288731710717818679969480139616039635803773520663910703950340653158737164251272207546666042246109754069901336109395477481894715201463512262881915897879656173450492687130617019L)), 
(20510351366590982808012091567957856006463372583225476196729621232427058891244033135266122422368717436144239282290429625258314878388582525963651477094032171523005588751883401036387241921835298594658532266157897208949317359209009097270105385659729255957703589479978391168865305462320634775118988106938901606751952632056230543695540783056461035075345750678931538428429459153361781179918080766729126394194487403427946652414723674963169068706923275636129758155825136855436208617286600132308056389508119591945124633888174292577799831104539350566037200433335913776420114862614183663180778379859218055065520128335773021662469L, (25878103089608291140623594201432925757230007902121621756433472828247700609520350341726170177382936606086989687845518714602107224768472125055903404115547731451407464943377373550649607446074794587264969002104771894755984102433762601990272009845089291344142864529479497281260992632162077586066954908004336055658532888083470571003952021493832352686556333226695274440535332563831099929217908259255108613004927475460191753780682263230319178268255948853782483094563386491679337944014630439702463021148483203826252584250009564185902373763190296336226860880395436642332924536801443702857155702673774298167076819213354229475371L, 6463297020610637310510773091288394653428198231981537762032668087173662441614494503598703761787541268197615886325016039089798472625890246726403030861336802798760437472343718386213807257842355522047276728738696630935756522997511203429148516931140567194499136794592572627970978873716072395626996408044151177252703869687848422896200423598678407885697326485289463708374259547101741694627819990576331676983298261853868284870065217975302450306584319086628702008262001742303765881792817774176299883986271713242197281445809960065129586015911263181582701561457683226983031669064465240687069937696589304827065650283145682330117L)), 
(20762522789190704370417048723559605979800816440675106352991852645680510406072967727818996228074432515875018958712127658059405054705227331238945663406216628669027888355320011188557119900569607446071064621271449777589761081487990982267138674331324324012224786679299772722311042910396304432106940236926462093996976223189225644680921415446499960991126185232742387687873612961904212984750532692044390484051848131788900973648473930053260991791714123014855965350024392650871658798066363812925440629938378850586347582908300791143134876379807231694470641266150822433766811956926075815480896321859722567813326182368090149888623L, (15580473152390168028873333646647147988415331540916094697029396082196662161238681595884266855258794985955582754869654649170384832108628950658400672241391650998398633799650282299991848023002112786187933052977829241644699625489086695027433455346309518428680913131660178051588375169093825633135477647016788791318559997185545543237557709466020710339672066054666915660258055141083612602304132513030215951081003484017901960152821983638370382683517819986739669753271614453658983719506653788142182191801218940251353919358629263335390272183522957932221047638782585727566925392765574281843569931902127382992278246674769447682563L, 14035502922137342273066543084585209695290111620414421404947665227866084897975365101182821806438823529882205613474387034691958654206281911273683994009264684513562249351640883593194189543859555543001733725440985068493782233307576513650902780799543120169017835305262196066158131982199759924347874175665350023903677088624679107483206475797963555451550162452765089545231370207016617233871009584126921841225863392083878804694309587408273696124211998727108656277859940698584629557238494789456236806391342571567559364359114832373354357419954577700242762446411199587596468040787549933412915463551947471558719532526944125397903L)), 
(37730268286452145171134987266616501426437405101719098584948779561396192433838888172558418113737683675677115423249435573805520630060012259627757103712503102342590991271285242532448263489802389534459028361178383615689697807912909791368881928909361754814208960898017862087881220951696749342503030965844084556673657764066844359055381688480247813472661906199277657060185810231715847789587398588476800218080909698624990237208144252399386774054658653332862260964819342243645287804097239751179392212217880777521101671779526324564013366513765208272423058247375357687113620181193046132075652310662632947839745937582713775919219L, (27271612445379199458795895797711786238098637558106584153799037428909180410339277716203985838926439759152646705126794571012627516898262331010361066941831177238628443766082068421189736030396805145083083282686798308347779983467680172267240379770522373057187711828861467911012451984155975082619306159355946646349287507614946094688666747186052486820429799343320677383038029902781545556398143393072758925513045284700329681492195678143767315988087557979879560754104840515269558743723030979669146922215917534800295976888483309514296801237949896639151203082520764921753646957798844158115010086129448338730192611242994726462393L, 13109358725536157723453051560537891594139392993099555483153963497393033982660388304412832051469333700374375791300133658207585483001587046613122258785100457977601179702342443136514567929234464402777072734869639828803612369692252250884448341249022943735540947498445177274012712373230765255507325779729606442658156888913927865513816129617857785537649451513547499403673104551766828340812100801821127634079887619410595105765877206329269772064887288559204435397059802095009122609528903144418075115655716542275318555781740664051112159192882153332952582032619442107972484873981090953203564917105178958388189682477906250987143L)), 
(35063411893376502761206667995449983716759886100639453549495242449311902941932495971955721176059213391999328664548774009816070735126616685992027947367758102605265790922530441841374295293942256254305546829049649988697097513240592534261819094671939150917634369636093702318935672648015395001481406891279456758823514466942358531402901219438099799617498118768423556447714474619599107688890261561573241458339471542294211557375147877103212829795482642634112735813821431941628164362063022362100276787359434292177361219078009599228094590981466877624297900080314609389247702491798879372013926200542138494707844074930298576913581L, (25807811369938493239152482882934678981180494162597887820850879395831831407255420293717220616122593335328459935860144797433957736554776510069835194575264904099271078131460672475516033793895696801631742787568462027134251106943032535501046667663847753174311950002997605019609318013826456108246622289656132834938630074763867798400772072785690046213138532641033131283346960280787212692417621222999680443728802801641037577140694963402252410913623092211189449844862371143932610146941368538249681681309708025415161776034077532282509487935813956579410458136231929147860488030330089095132440207713295743752934466481405768642363L, 20536007132247274778103394991080864313157206855494700473554715799498607961327428366662060157571446528947033551240932411754591371303379496792623908346363480193737268033515855248316732652473415765005083607663019613090590656699420889289101985687735342032902972470974205665179214530302267362883927514854869210279070076232220282553533808696349311350366921892963900998888693064792044200079229828614328805813536291713400229417995218160575887960849375039445854938669828667457273968109179726936439561363897635080620360434277562906580901543514397824706389407949294059669730873185095293638834215026625618346798028417349712174421L))]

user_pks = []								# Create list of public keys of users
key_dict = {}								# Create dictionary for key pairs. Dictionary keys are pk, values are sk
bank = {}									# Create dictionary for bank. Dictionary keys are pk, values are coins in account

# for i in range(total_users):
	# sk, pk = create_user()
	# user_pks.append(pk)
	# key_dict[pk] = [sk]
	# bank[pk] = []
	
for i in range(total_users):
	sk, pk = (hardcoded[i][0], hardcoded[i][1])
	user_pks.append(pk)
	key_dict[pk] = sk
	bank[pk] = []

print "Initializing transaction queue"
tq = init_transaction_queue()

print "Initializing ledger\n"
ledger = [init_ledger(key_dict[user_pks[0]], user_pks[0], bank, tq)]

# User 0 should have 10 coins (from genesis block mint)
# User 1 should have 0 coins
# User 2 should have 0 coins
print "Balance of user 0:", check_balance(user_pks[0], bank)
print "Balance of user 1:", check_balance(user_pks[1], bank)
print "Balance of user 2:", check_balance(user_pks[2], bank), "\n"

# User 0 creates a transaction to send 2 coins to user 1
print "Creating transaction from user 0 to user 1"
send_coins = bank[user_pks[0]][0:2]
transaction = gen_transaction(user_pks[0], key_dict[user_pks[0]], user_pks[1], send_coins, bank, tq, True)

# User 2 generates a block using the previous transaction
print "Generating block by user 2"
block = gen_block(len(ledger), key_dict[user_pks[2]], user_pks[2], tq, 1, bank, ledger[-1], 5)
if(ver_block(len(ledger), block, tq, bank, ledger, 5)): 
	print "Adding block to ledger\n"
	ledger.append(block)

# User 0 should have 8 coins 
# User 1 should have 2 coins
# User 2 should have 10 coins
print "Balance of user 0:", check_balance(user_pks[0], bank)
print "Balance of user 1:", check_balance(user_pks[1], bank)
print "Balance of user 2:", check_balance(user_pks[2], bank), "\n"
	
# User 0 creates a transaction to send 3 coins to user 1
# User 2 creates a transaction to send 4 coins to user 0
# User 2 creates a transaction to send the same 4 coins to user 1
print "Creating transaction from user 0 to user 1"
send_coins = bank[user_pks[0]][0:3]
transaction = gen_transaction(user_pks[0], key_dict[user_pks[0]], user_pks[1], send_coins, bank, tq, True)
print "Creating transaction from user 2 to user 0"
send_coins = bank[user_pks[2]][0:4]
transaction = gen_transaction(user_pks[2], key_dict[user_pks[2]], user_pks[0], send_coins, bank, tq, True)
print "Creating transaction from user 2 to user 1"
send_coins = bank[user_pks[2]][0:4]
transaction = gen_transaction(user_pks[2], key_dict[user_pks[2]], user_pks[1], send_coins, bank, tq, True)

# User 1 generates a block using the previous 3 transactions
print "Generating block by user 1"
block = gen_block(len(ledger), key_dict[user_pks[1]], user_pks[1], tq, 3, bank, ledger[-1], 5)
if(ver_block(len(ledger), block, tq, bank, ledger, 5)): 
	print "Adding block to ledger\n"
	ledger.append(block)

# User 0 should still have 8 coins
# User 1 should still have 2 coins
# User 2 should still have 10 coins
print "Balance of user 0:", check_balance(user_pks[0], bank)
print "Balance of user 1:", check_balance(user_pks[1], bank)
print "Balance of user 2:", check_balance(user_pks[2], bank), "\n"

# User 1 generates a block using the 2 valid transactions which were added back
print "Generating block by user 1"
block = gen_block(len(ledger), key_dict[user_pks[1]], user_pks[1], tq, 3, bank, ledger[-1], 5)
if(ver_block(len(ledger), block, tq, bank, ledger, 5)): 
	print "Adding block to ledger\n"
	ledger.append(block)

# User 0 should now have 9 coins
# User 1 should now have 15 coins
# User 2 should now have 6 coins
print "Balance of user 0:", check_balance(user_pks[0], bank)
print "Balance of user 1:", check_balance(user_pks[1], bank)
print "Balance of user 2:", check_balance(user_pks[2], bank), "\n"