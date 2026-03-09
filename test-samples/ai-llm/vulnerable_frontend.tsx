/**
 * Vulnerable AI/LLM Frontend Component - Test Sample
 * Contains intentional vulnerabilities for scanner testing.
 */

import React, { useState } from 'react';

// AI-KEY-001: OpenAI key in frontend
const openai_api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";

// AI-KEY-005: Generic API key
const api_key = "abcdefghijklmnopqrstuvwxyz12345678901234567890abcd";

interface ChatMessage {
  role: string;
  content: string;
}

function AIChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');

  const sendMessage = async (user_input: string) => {
    // AI-PINJ-001: User input directly in prompt
    const prompt = `You are a helpful assistant. Answer this question: ${user_input}`;

    // AI-PINJ-003: System prompt with interpolation
    const system_prompt = `You are an AI for ${user_input}. Be helpful.`;

    const response = await fetch('/api/chat', {
      method: 'POST',
      body: JSON.stringify({
        messages: [
          { role: 'system', content: system_prompt },
          { role: 'user', content: prompt }
        ],
        api_key: openai_api_key,
      }),
    });

    const data = await response.json();

    // AI-OUT-001: Rendering LLM output as HTML
    document.getElementById('response')!.innerHTML = data.response;

    return data;
  };

  return (
    <div>
      <input value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={() => sendMessage(input)}>Send</button>
      {/* AI-OUT-001: dangerouslySetInnerHTML with AI output */}
      <div dangerouslySetInnerHTML={{ __html: response.content }} />
      <div dangerouslySetInnerHTML={{ __html: ai_output }} />
    </div>
  );
}

export default AIChat;
