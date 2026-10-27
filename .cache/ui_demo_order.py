from pathlib import Path
p = Path('templates/demo.html')
s = p.read_text(encoding='utf-8')
a = s.index('<div class="section-heading">')
b = s.index('{% if outcome %}<section', a)
grid = s[a:b]
s = s[:a] + s[b:]
s = s.replace('{% endblock %}', grid + '{% endblock %}')
p.write_text(s, encoding='utf-8')
