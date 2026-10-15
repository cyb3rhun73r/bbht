import { useRef, useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, FlatList, KeyboardAvoidingView,
  Platform, StyleSheet, SafeAreaView, StatusBar, ActivityIndicator,
} from 'react-native';

// Apne computer ka local IP daalo (same Wi-Fi), ya deployed server ka https URL.
// Example: 'http://192.168.1.10:8000'
const API_URL = 'http://192.168.1.10:8000';

export default function App() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: '🙏 Kalyan ho, Parth. Bolo — tumhare man mein kaun sa kurukshetra chal raha hai?' },
  ]);
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const list = useRef(null);

  async function send() {
    const t = text.trim();
    if (!t || loading) return;
    const next = [...messages, { role: 'user', content: t }];
    setMessages(next);
    setText('');
    setLoading(true);
    try {
      const r = await fetch(`${API_URL}/api/chat/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: next.slice(1) }), // skip local greeting
      });
      const data = await r.json();
      setMessages([...next, { role: 'assistant', content: data.reply }]);
    } catch {
      setMessages([...next, { role: 'assistant', content: 'Sampark nahi ho paya. API_URL aur Wi-Fi check karo.' }]);
    }
    setLoading(false);
  }

  return (
    <SafeAreaView style={s.root}>
      <StatusBar barStyle="light-content" />
      <View style={s.header}>
        <Text style={s.title}>🪈 Krishna Vani</Text>
        <Text style={s.sub}>Apni uljhan batao, Parth</Text>
      </View>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <FlatList
          ref={list}
          data={messages}
          keyExtractor={(_, i) => String(i)}
          contentContainerStyle={{ padding: 14, gap: 10 }}
          onContentSizeChange={() => list.current?.scrollToEnd({ animated: true })}
          renderItem={({ item }) => (
            <View style={[s.bubble, item.role === 'user' ? s.user : s.krishna]}>
              <Text style={s.msg} selectable>{item.content}</Text>
            </View>
          )}
          ListFooterComponent={loading ? <ActivityIndicator color="#e8b44c" style={{ margin: 10 }} /> : null}
        />
        <View style={s.inputRow}>
          <TextInput
            style={s.input}
            value={text}
            onChangeText={setText}
            placeholder="Apni situation likho…"
            placeholderTextColor="#999"
            multiline
          />
          <TouchableOpacity style={[s.btn, loading && { opacity: 0.5 }]} onPress={send} disabled={loading}>
            <Text style={s.btnText}>Bhejo</Text>
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0f1226' },
  header: { alignItems: 'center', padding: 12, borderBottomWidth: 1, borderBottomColor: '#ffffff18' },
  title: { color: '#e8b44c', fontSize: 20, fontWeight: '700' },
  sub: { color: '#f3ecda', opacity: 0.7, fontSize: 12 },
  bubble: { padding: 12, borderRadius: 16, maxWidth: '88%' },
  user: { backgroundColor: '#2b3166', alignSelf: 'flex-end' },
  krishna: { backgroundColor: '#1a1e3c', borderWidth: 1, borderColor: '#e8b44c40', alignSelf: 'flex-start' },
  msg: { color: '#f3ecda', fontSize: 16, lineHeight: 24 },
  inputRow: { flexDirection: 'row', gap: 8, padding: 10, alignItems: 'flex-end' },
  input: { flex: 1, backgroundColor: '#1a1e3c', color: '#f3ecda', borderRadius: 12, padding: 12, maxHeight: 120, fontSize: 16 },
  btn: { backgroundColor: '#e8b44c', borderRadius: 12, paddingHorizontal: 18, paddingVertical: 14 },
  btnText: { color: '#2a1d00', fontWeight: '700' },
});
