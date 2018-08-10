import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.util.Date;
import java.util.TimeZone;

public class EosTransaction {
    private static final char[] CHARMAP = ".12345abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] HEX = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    private static final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    static {
        format.setTimeZone(TimeZone.getTimeZone(ZoneId.of("GMT")));
    }

    private static void packByte(ByteBuffer buf, int value) {
        buf.put((byte)(value & 0xff));
    }

    private static void packShort(ByteBuffer buf, int value) {
        buf.put((byte)(value & 0xff));
        buf.put((byte)((value >> 8) & 0xff));
    }

    private static void packInt(ByteBuffer buf, long value) {
        buf.put((byte)(value & 0xff));
        buf.put((byte)((value >> 8) & 0xff));
        buf.put((byte)((value >> 16) & 0xff));
        buf.put((byte)((value >> 24) & 0xff));
    }

    private static void packLong(ByteBuffer buf, long value) {
        buf.put((byte)(value & 0xff));
        buf.put((byte)((value >> 8) & 0xff));
        buf.put((byte)((value >> 16) & 0xff));
        buf.put((byte)((value >> 24) & 0xff));
        buf.put((byte)((value >> 32) & 0xff));
        buf.put((byte)((value >> 40) & 0xff));
        buf.put((byte)((value >> 48) & 0xff));
        buf.put((byte)((value >> 56) & 0xff));
    }

    private static void packVarInt(ByteBuffer buf, long value) {
        do {
            byte b = (byte)(value & 0x7f);
            value = value >> 7;
            b |= (value > 0 ? 1 : 0) << 7;
            buf.put(b);
        } while (value > 0);
    }

    private static int charToInt(char x) {
        if (x >= '0' && x <= '9') {
            return x - '0';
        }
        return 10 + x - 'a';
    }

    private static void packBinary(ByteBuffer buf, String value) {
        packVarInt(buf, value.length()/2);
        for (int i=0; i<value.length()/2; i++) {
            int c1 = charToInt(value.charAt(i*2));
            int c2 = charToInt(value.charAt(i*2+1));
            buf.put((byte)((c1<<4)|c2));
        }
    }

    private static void packString(ByteBuffer buf, String value) {
        packVarInt(buf, value.length());
        buf.put(value.getBytes());
    }

    private static int charToSymbol(char c) {
        if (c >= 'a' && c <= 'z') {
            return (c - 'a') + 6;
        }
        if (c >= '1' && c <= '5') {
            return (c - '1') + 1;
        }
        return 0;
    }

    private static long base32Encode(String name) {
        char[] nameChar = name.toCharArray();
        long value = 0;
        int len = nameChar.length;

        for (int i = 0; i <= 12; ++i ) {
            long c = 0;
            if (i < len && i <= 12) {
                c = charToSymbol(nameChar[i]);
            }

            if (i < 12) {
                c &= 0x1f;
                c <<= 64-5*(i+1);
            }
            else {
                c &= 0x0f;
            }

            value |= c;
        }

        return value;
    }

    private static String longToString(long value) {
        char[] str = new char[]{'.','.','.','.','.','.','.','.','.','.','.','.','.'}; // 13 '.'s

        for (int i = 0; i <= 12; ++i ) {
            char c = CHARMAP[(int)(value & (i == 0 ? 0x0f : 0x1f))];
            str[12-i] = c;
            value >>= (i == 0 ? 4 : 5);
        }

        int lastNonDot = str.length - 1;
        while (lastNonDot > 0 && str[lastNonDot] == '.') {
            lastNonDot--;
        }
        return new String(str, 0, lastNonDot + 1);
    }

    public static EosTransaction parseJson(JSONObject tx) {
        EosTransaction result = new EosTransaction();
        result.set(tx);
        return result;
    }

    class PermissionLevel {
        private String actor;
        private String permission;

        PermissionLevel() {

        }

        PermissionLevel(String a, String p) {
            actor = a;
            permission = p;
        }

        void pack(ByteBuffer buf) {
            packLong(buf, base32Encode(actor));
            packLong(buf, base32Encode(permission));
        }

        void set(JSONObject obj) {
            actor = obj.getString("actor");
            permission = obj.getString("permission");
        }

        JSONObject toJson() {
            JSONObject result = new JSONObject();
            result.put("actor", actor);
            result.put("permission", permission);
            return result;
        }
    }

    class Action {
        private String account;
        private String name;
        private PermissionLevel[] authorization;
        private String data;

        Action() {

        }

        Action(String acc, String na, String act, String per, String da) {
            account = acc;
            name = na;
            authorization = new PermissionLevel[1];
            authorization[0] = new PermissionLevel(act, per);
            data = da;
        }

        void pack(ByteBuffer buf) {
            packLong(buf, base32Encode(account));
            packLong(buf, base32Encode(name));
            packVarInt(buf, authorization.length);
            for (PermissionLevel auth : authorization) {
                auth.pack(buf);
            }
            packBinary(buf, data);
        }

        void set(JSONObject obj) {
            account = obj.getString("account");
            name = obj.getString("name");
            JSONArray auth = obj.getJSONArray("authorization");
            authorization = new PermissionLevel[auth.length()];
            for (int i = 0; i < authorization.length; i++) {
                authorization[i] = new PermissionLevel();
                authorization[i].set(auth.getJSONObject(i));
            }
            data = obj.getString("data");
        }

        JSONObject toJson() {
            JSONObject result = new JSONObject();
            result.put("account", account);
            result.put("name", name);
            JSONArray array = new JSONArray();
            for (PermissionLevel level : authorization) {
                array.put(level.toJson());
            }
            result.put("authorization", array);
            result.put("data", data);
            return result;
        }
    }

    /* unsupported feature yet */
    class ExtentionType {
        private int num;
        private String data;

        void pack(ByteBuffer buf) {
            packInt(buf, num);
            packBinary(buf, data);
        }

        void set(JSONObject obj) {
            num = (short)obj.getInt("unknown");
            data = obj.getString("unknown");
        }

        /* not used */
        JSONObject toJson() {
            return null;
        }
    }


    private long expiration;
    private int refBlockNum;
    private long refBlockPrefix;
    private int maxNetUsageWords;
    private int maxCpuUsageMs;
    private int delaySec;
    private Action[] contextFreeActions;
    private Action[] actions;

    private ExtentionType[] transactionExtension;
    private String[] signature;
    private String[] contextFreeData;

    private EosTransaction() {}

    public EosTransaction(long exp, int refNum, long refPre, int maxNet, int maxCpu, int delay, String account, String name, String actor, String permission, String data) {
        expiration = exp;
        refBlockNum = refNum;
        refBlockPrefix = refPre;
        maxNetUsageWords = maxNet;
        maxCpuUsageMs = maxCpu;
        delaySec = delay;
        contextFreeActions = new Action[0];
        actions = new Action[1];
        actions[0] = new Action(account, name, actor, permission, data);
        transactionExtension = new ExtentionType[0];
        signature = new String[0];
        contextFreeData = new String[0];
    }

    public String[] getSignature() {
        return signature;
    }

    public String pack() {
        ByteBuffer buf = ByteBuffer.allocate(8192);
        pack(buf);
        buf.flip();
        int len = buf.limit();
        StringBuilder result = new StringBuilder();
        for (int i=0; i<len; i++) {
            int x = buf.get() & 0xFF;
            result.append(HEX[x/16]).append(HEX[x%16]);
        }
        return result.toString();
    }

    private void pack(ByteBuffer buf) {
        packInt(buf, expiration);
        packShort(buf, refBlockNum);
        packInt(buf, refBlockPrefix);
        packVarInt(buf, maxNetUsageWords);
        packByte(buf, maxCpuUsageMs);
        packVarInt(buf, delaySec);

        packVarInt(buf, contextFreeActions.length);
        for (Action act : contextFreeActions) {
            act.pack(buf);
        }
        packVarInt(buf, actions.length);
        for (Action act : actions) {
            act.pack(buf);
        }

        packVarInt(buf, transactionExtension.length);
        for (ExtentionType ext : transactionExtension) {
            ext.pack(buf);
        }

        packVarInt(buf, signature.length);
        for (String sig : signature) {
            packString(buf, sig);
        }

        packVarInt(buf, contextFreeData.length);
        for (String cfd : contextFreeData) {
            packBinary(buf, cfd);
        }
    }

    public void set(JSONObject obj) {
        String expireTime = obj.getString("expiration");
        try {
            expiration = (int)(format.parse(expireTime).getTime() / 1000);
            refBlockNum = obj.getInt("ref_block_num");
            refBlockPrefix = obj.getLong("ref_block_prefix");
            maxNetUsageWords = obj.getInt("max_net_usage_words");
            maxCpuUsageMs = (byte)obj.getInt("max_cpu_usage_ms");
            delaySec = obj.getInt("delay_sec");

            JSONArray cfa = obj.getJSONArray("context_free_actions");
            contextFreeActions = new Action[cfa.length()];
            for (int i = 0; i < contextFreeActions.length; i++) {
                contextFreeActions[i] = new Action();
                contextFreeActions[i].set(cfa.getJSONObject(i));
            }

            JSONArray acts = obj.getJSONArray("actions");
            actions = new Action[acts.length()];
            for (int i = 0; i < actions.length; i++) {
                actions[i] = new Action();
                actions[i].set(acts.getJSONObject(i));
            }

            // eosio does not support this yet
            transactionExtension = new ExtentionType[0];

            JSONArray sigs = obj.getJSONArray("signatures");
            signature = new String[sigs.length()];
            for (int i = 0; i < sigs.length(); i++) {
                signature[i] = sigs.getString(i);
            }

            JSONArray cfd = obj.getJSONArray("context_free_data");
            contextFreeData = new String[cfd.length()];
            for (int i = 0; i < cfd.length(); i++) {
                contextFreeData[i] = cfd.getString(i);
            }
        }
        catch (ParseException e) {

        }
    }

    public JSONObject toJson() {
        JSONObject result = new JSONObject();
        result.put("expiration", format.format(new Date(expiration * 1000l)));
        result.put("ref_block_num", refBlockNum);
        result.put("ref_block_prefix", refBlockPrefix);
        result.put("max_net_usage_words", maxNetUsageWords);
        result.put("max_cpu_usage_ms", maxCpuUsageMs);
        result.put("delay_sec", delaySec);

        JSONArray array = new JSONArray();
        for (Action act : contextFreeActions) {
            array.put(act.toJson());
        }
        result.put("context_free_actions", array);

        array = new JSONArray();
        for (Action act : actions) {
            array.put(act.toJson());
        }
        result.put("actions", array);

        result.put("transaction_extensions", new JSONArray());

        array = new JSONArray();
        for (String sig : signature) {
            array.put(sig);
        }
        result.put("signatures", array);

        array = new JSONArray();
        for (String cfd : contextFreeData) {
            array.put(cfd);
        }
        result.put("context_free_data", array);
        return result;
    }

    private static long getBlockPrefix(String id) {
        // convert 6547c36c to 6cc34765
        String reversed = id.substring(6, 8) + id.substring(4, 6) + id.substring(2,4) + id.substring(0, 2);
        return Long.parseLong(reversed, 16);
    }

    // for test
    public static void main(String[] args) {
        int blockNum = 10369807;
        String blockId = "009e3b0fba79833b24eaf68724fc45b6a1c9966a189e8554ab91cdc0728e925a";
        String from = "youraccount1";
        String bin = "01020304"; // this is just sample, it can be obtained by abi_json_to_bin

        EosTransaction unsignedTx = new EosTransaction(System.currentTimeMillis() / 1000 + 60, blockNum & 0xFFFF, getBlockPrefix(blockId.substring(16, 24)), 0, 0, 0, "eosio.token", "transfer", from, "active", bin);
        System.out.println(unsignedTx.pack());
    }
}
