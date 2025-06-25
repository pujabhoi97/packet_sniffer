const ctx = document.getElementById('packetChart').getContext('2d');
const chart = new Chart(ctx, {
  type: 'bar',
  data: {
    labels: ['TCP', 'HTTP', 'DNS'],
    datasets: [{
      label: 'Packet Count',
      data: [0, 0, 0],
      backgroundColor: ['blue', 'green', 'orange']
    }]
  },
  options: {
    responsive: true,
    scales: {
      y: { beginAtZero: true }
    }
  }
});

function updateChart() {
  fetch('/data')
    .then(res => res.json())
    .then(data => {
      chart.data.datasets[0].data = [
        data.counts.tcp,
        data.counts.http,
        data.counts.dns
      ];
      chart.update();

      document.getElementById('http_hosts').innerHTML =
        data.http_hosts.map(h => `<li>${h}</li>`).join('');
      document.getElementById('dns_queries').innerHTML =
        data.dns_queries.map(q => `<li>${q}</li>`).join('');
      document.getElementById('tcp_sources').innerHTML =
        data.tcp_sources.map(s => `<li>${s}</li>`).join('');
    });
}

setInterval(updateChart, 1000);
